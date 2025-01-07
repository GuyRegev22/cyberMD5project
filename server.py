import socket
import threading
import sqlite3
import hashlib
from aes_methods import decrypt_with_rsa, generate_rsa_keys
from cryptography.hazmat.primitives import serialization
import protocol
import signal
import sys


class Server:
    """
    Server class to handle multiple client connections, user authentication, and task distribution.
    This class supports user registration, login, task allocation (ranges), and client disconnection handling.
    Database is used to store user information and manage assigned/unassigned tasks.
    """

    def __init__(self, IP, PORT=5555):
        """
        Initialize the server object with IP, port, and default parameters.

        Args:
            IP (str): IP address to bind the server.
            PORT (int): Port number to listen for client connections.
        """
        self.server_private_key, self.server_public_key = generate_rsa_keys()
        self.IP = IP
        self.PORT = PORT
        # self.range = (3600000000, 3700000000)  # Default starting range
        self.range = (10000000000, 10100000000)
        self.queue = []  # Queue to hold unprocessed ranges
        self.client_sockets = []  # Active client sockets
        self.TARGET = "18dfb26f95f143c77d2ca5b31bc43f1c".lower()  # Target hash for validation
        self.INC = 10000000 #Increments each itertion of range
        self.found = False  # Flag to indicate if the target has been found
        self.num = None  # Store the number that matches the target hash
        self.lock = threading.Lock()  # Lock for thread-safe operations
        self.stop_event = threading.Event()  # Event to signal shutdown

    def create_socket(self):
        """
        Create and bind the server socket, then start listening for client connections.
        """
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.IP, self.PORT))
        self.server_socket.listen()
        print(f"Server is up and running on port: {self.PORT}")
    
    def handle_key_exchange(self, cl_socket):
        client_hello = protocol.server_protocol.get_msg_plaintext(cl_socket).decode(encoding="latin-1")
        while client_hello != "Client hello":
            client_hello = protocol.server_protocol.get_msg_plaintext(cl_socket).decode(encoding="latin-1")
        serialized_server_public_key = self.server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )# maybe dont use in plain text encode cause it wont work or maybe check if its in bytes
        protocol.server_protocol.send_msg_plaintext(cl_socket, serialized_server_public_key)    
        encrypted_aes_key = protocol.server_protocol.get_msg_plaintext(cl_socket)
        aes_key = decrypt_with_rsa(self.server_private_key, encrypted_aes_key)
        return aes_key
    
    def setup_database(self):
        """
        Create and initialize the SQLite database for user and mission management.
        Ensures tables for users and missions exist before starting server operations.
        """
        with self.lock:
            conn = sqlite3.connect("demo.db")
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                                username TEXT PRIMARY KEY,
                                password TEXT NOT NULL,
                                phone TEXT NOT NULL
                            )''')
            cursor.execute('''CREATE TABLE IF NOT EXISTS missions (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                username TEXT NOT NULL,
                                range TEXT NOT NULL,
                                done BOOLEAN NOT NULL CHECK (done IN (0, 1))
                            )''')
            conn.commit()
            conn.close()
            print("Database initialized.")

    def handle_client(self, cl_socket):
        """
        Handle communication with a single connected client.

        Args:
            cl_socket (socket): The client socket object.
        """
        aes_key = self.handle_key_exchange(cl_socket)
        username = None  # Store the current client's username
        try:
            while not self.stop_event.is_set():
                try:
                    parsed_req = protocol.server_protocol.get_request(cl_socket, aes_key=aes_key)
                    print(parsed_req)
                    if parsed_req[0] == '': 
                        break

                    if username is None:  # Client not authenticated
                        match parsed_req[0]:
                            case 'REG':  # Registration
                                ret_code = self.register_user(username=parsed_req[1], password=parsed_req[2], phone=parsed_req[3])
                                # if ret_code:
                                #     username = parsed_req[1]
                                protocol.server_protocol.send_register_success(success=ret_code, cl_socket=cl_socket, aes_key=aes_key)

                            case 'LOGIN':  # Login
                                ret_code = self.authenticate_user(username=parsed_req[1], password=parsed_req[2])
                                if ret_code:
                                    username = parsed_req[1]
                                    print(f"[*] {username} Logged In [*]")
                                protocol.server_protocol.send_login_success(aes_key=aes_key, success=ret_code, cl_socket=cl_socket)

                            case _:  # Error: Unauthenticated action
                                protocol.server_protocol.send_error(aes_key=aes_key, cl_socket=cl_socket, error_msg="Error: Client is not logged in!")
                                continue
                    else:  # Authenticated client actions
                        match parsed_req[0]:
                            case 'GETRANGE':  # Request range
                                handle_cal = self.handle_calc_req(aes_key, username, cl_socket)
                                if handle_cal:
                                    break  # End session if the target was found

                            case 'FOUND':  # Target found
                                self.valid_finding(parsed_req[1])

                            case 'LOGOUT':  # Client logout
                                print(f"{username} logged out.")
                                self.load_unfinished_missions(username)
                                username = None
                            case _:  # Unknown request
                                protocol.server_protocol.send_error(aes_key, cl_socket=cl_socket, error_msg="Error: Unknown request.")
                                break
                except (ConnectionResetError, BrokenPipeError):
                    print(f"Client {username or 'unknown'} disconnected unexpectedly.")
                    break
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            if username:
                self.load_unfinished_missions(username) #I know it may be weird
            print(f"Cleaning up for client: {username}")
            with self.lock:
                if cl_socket in self.client_sockets:
                    self.client_sockets.remove(cl_socket)
            print(f"Client {username or 'unknown'} disconnected.")
            cl_socket.close()

    def register_user(self, username, password, phone):
        """
        Register a new user in the database.

        Args:
            username (str): Username of the client.
            password (str): Password of the client.
            phone (str): Phone number of the client.

        Returns:
            bool: True if registration is successful, False otherwise.
        """
        hashed_pass = hashlib.md5(password.encode()).hexdigest()
        with self.lock:
            conn = sqlite3.connect("demo.db")
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO users (username, password, phone) VALUES (?, ?, ?)",
                               (username, hashed_pass, phone))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False
            finally:
                conn.close()

    def authenticate_user(self, username, password):
        """
        Authenticate a user against the database.

        Args:
            username (str): Username of the client.
            password (str): Password of the client.

        Returns:
            bool: True if the credentials are valid, False otherwise.
        """
        hashed_pass = hashlib.md5(password.encode()).hexdigest()
        with self.lock:
            conn = sqlite3.connect("demo.db")
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_pass))
            user = cursor.fetchone()
            conn.close()
            return user is not None

    def handle_calc_req(self, aes_key, username, sock):
        """
        Handle range calculation requests from a client.

        Args:
            username (str): Username of the client requesting a range.
            sock (socket): Client socket to send the range.

        Returns:
            bool: True if the target is found, False otherwise.
        """        
        with self.lock:
            if self.found:
                protocol.server_protocol.return_check(aes_key=aes_key, is_found=self.found, cl_socket=sock, num_found=self.num)
                return True

            conn = sqlite3.connect("demo.db")
            cursor = conn.cursor()
            try:
                cursor.execute("UPDATE missions SET done = 1 WHERE username = ? AND done = 0", (username,))
                conn.commit()

                if not self.queue:
                    new_range_start = self.range[0] + self.INC
                    new_range_end = new_range_start + self.INC
                    self.range = (new_range_start, new_range_end)
                else:
                    new_range_start, new_range_end = self.queue.pop()
                new_range = f"{new_range_start}-{new_range_end}"

                cursor.execute("INSERT INTO missions (username, range, done) VALUES (?, ?, ?)", (username, new_range, 0))
                conn.commit()

                protocol.server_protocol.send_range(sock, aes_key, new_range_start, new_range_end, self.TARGET)
            except sqlite3.Error as e:
                print(f"Database error: {e}")
                protocol.server_protocol.send_error(sock, aes_key, "Server error while processing mission request.")
            finally:
                conn.close()

    def valid_finding(self, num: int):
        """
        Validate if the provided number matches the target hash.

        Args:
            num (int): Number sent by the client.
        """
        with self.lock:
            result = hashlib.md5(f"{num}".encode()).hexdigest()
            if result == self.TARGET:
                print(f"\nTarget found: {num}\n")
                self.num = num
                self.found = True

    def load_unfinished_missions(self, user=None):
        """
        Load all unfinished missions from the database into the queue.
        Optionally, load missions only for a specific user.
        This ensures that any previously assigned but incomplete tasks
        are re-queued for reassignment.

        Args:
            user (str, optional): Username to filter unfinished missions. If None, load for all users.
        """
        with self.lock:
            conn = sqlite3.connect("demo.db")
            cursor = conn.cursor()
            try:
                if user:
                    # Load unfinished missions for a specific user
                    cursor.execute("SELECT range FROM missions WHERE done = 0 AND username = ?", (user,))
                else:
                    # Load unfinished missions for all users
                    cursor.execute("SELECT range FROM missions WHERE done = 0")
                unfinished_missions = cursor.fetchall()

                if len(unfinished_missions) > 0:
                    if user:
                        # Delete unfinished missions for the specific user
                        cursor.execute("DELETE FROM missions WHERE done = 0 AND username = ?", (user,))
                    else:
                        # Delete all unfinished missions
                        cursor.execute("DELETE FROM missions WHERE done = 0")
                    conn.commit()

                for mission in unfinished_missions:
                    range_start, range_end = map(int, mission[0].split('-'))
                    self.queue.append((range_start, range_end))
                print(f"Loaded {len(unfinished_missions)} unfinished missions into the queue.")
            except sqlite3.Error as e:
                print(f"Database error while loading unfinished missions: {e}")
            finally:
                conn.close()

    def run(self):
        """
        Start accepting client connections and handle them in separate threads.
        """
        while not self.stop_event.is_set():
            try:
                client_socket, addr = self.server_socket.accept()
                self.client_sockets.append(client_socket)
                print(f"Accepted connection from {addr}")
                client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_handler.start()
            except OSError:
                break

    def shutdown(self):
        """
        Cleanly shut down the server.
        """
        self.stop_event.set()
        self.server_socket.close()
        for sock in self.client_sockets:
            sock.close()
        print("Server shut down cleanly.")


def signal_handler(sig, frame):
    """
    Handle Ctrl+C signal for graceful server shutdown.
    """
    print("\nShutting down the server...")
    server_instance.shutdown()
    sys.exit(0)


def main():
    """
    Main entry point for the server program.
    """
    global server_instance
    server_instance = Server("0.0.0.0", 5555)
    signal.signal(signal.SIGINT, signal_handler)
    server_instance.setup_database()
    server_instance.load_unfinished_missions()
    server_instance.create_socket()
    server_instance.run()


if __name__ == "__main__":
    main()