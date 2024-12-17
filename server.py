import socket
import threading
import sqlite3
import hashlib
import protocol

'''
Server class to handle multiple client connections, user authentication, and task distribution.
This class supports user registration, login, task allocation (ranges), and client disconnection handling.
Database is used to store user information and manage assigned/unassigned tasks.
'''

class server:
    # Initialize variables and start the server
    def __init__(self, IP, PORT):
        '''
        Initialize the server object with IP, port, and default parameters.

        Args:
            IP (str): IP address to bind the server.
            PORT (int): Port number to listen for client connections.
        '''
        self.ip = IP
        self.PORT = PORT
        self.range = (3600000000, 3700000000)  # Default starting range
        self.queue = []  # Queue to hold unprocessed ranges
        self.client_sockets = []  # Active client sockets
        self.TARGET = "EC9C0F7EDCC18A98B1F31853B1813301".lower()  # Target hash for validation
        self.INC = 10000000
        self.found = False  # Flag to indicate if the target has been found
        self.num = None
    def create_socket(self):
        '''
        Create and bind the server socket, then start listening for client connections.
        '''
        self.my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.my_socket.bind((self.ip, self.PORT))
        self.my_socket.listen()
        print(f"Server is up and running on port:{self.PORT}")

    def setup_database(self):
        '''
        Create and initialize the SQLite database for user and mission management.
        '''
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
        print("Database created")

    def handle_client(self, cl_socket):
        '''
        Handle communication with a single connected client.

        Args:
            cl_socket (socket): The client socket object.
        '''
        username = None  # Temporary storage for the session's username
        try:
            while True:
                parsed_req = protocol.server_protocol.get_request(cl_socket)

                if username == None: 
                    match parsed_req[0]:
                        case 'REG':
                            ret_code = self.register_user(username=parsed_req[1], password=parsed_req[2], phone=parsed_req[3])
                            if ret_code:
                                username = parsed_req[1]
                            protocol.server_protocol.send_register_success(success=ret_code, cl_socket=cl_socket)

                        case 'LOGIN':
                            ret_code = self.authenticate_user(username=parsed_req[1], password=parsed_req[2])
                            if ret_code:
                                username = parsed_req[1]
                                print(f"[*] {username} Logged In [*]")
                            protocol.server_protocol.send_login_success(success=ret_code, cl_socket=cl_socket)
                        case _: #Error cases
                            protocol.server_protocol.send_error(cl_socket=cl_socket, error_msg="[*]Error: Client is not logged in! [*]")
                            continue
                else:
                    match parsed_req[0]:
                        case 'GETRANGE':
                            handle_cal = self.handle_calc_req(parsed_req[1], cl_socket)
                            if handle_cal:
                                break  # Exit early like `break`

                        case 'FOUND':
                            self.valid_finding(parsed_req[1])

                        case 'LOGOUT':
                            print("Some client logged out!")
                            break  # Exit early like `break`

                        case _:
                            protocol.server_protocol.send_error(cl_socket=cl_socket, error_msg="[*]Error: Unknown request! [*]")
                            break  # Default case, exit
        except WindowsError:
            print("Client disconnected unexpectedly")
        except Exception as e:
            print(f"[*]Error: {e} [*]")
        finally:
            if username:
                self.cleanup_unfinished_missions(username)
            print(f"Client Disconnected with the username: {username}")
            self.client_sockets.remove(cl_socket)
            cl_socket.close()

    def register_user(self, username, password, phone):
        '''
        Register a new user in the database.

        Args:
            username (str): Username of the client.
            password (str): Password of the client.
            phone (str): Phone number of the client.

        Returns:
            bool: True if registration is successful, False if the username is taken.
        '''
        conn = sqlite3.connect("demo.db")
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password, phone) VALUES (?, ?, ?)",
                           (username, password, phone))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    def authenticate_user(self, username, password):
        '''
        Authenticate a user against the database.

        Args:
            username (str): Username of the client.
            password (str): Password of the client.

        Returns:
            bool: True if the credentials are valid, False otherwise.
        '''
        conn = sqlite3.connect("demo.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        conn.close()
        return user is not None

    def handle_calc_req(self, username, sock):
        '''
        Handle range calculation requests from a client.

        Args:
            username (str): Username of the client requesting a range.
            sock (socket): Client socket to send the range.

        Returns:
            bool: True if the target is found, False otherwise.
        '''
        if self.found:
            protocol.server_protocol.return_check(is_found=self.found, cl_socket=sock, num_found=self.num)
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

            protocol.server_protocol.send_range(sock, new_range_start, new_range_end, self.TARGET)

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            protocol.server_protocol.send_error(sock, "Server error while processing mission request.")
        finally:
            conn.close()

    def valid_finding(self, num: int):
        '''
        Validate if the provided number matches the target hash.

        Args:
            num (int): Number sent by the client.
        '''
        result = hashlib.md5(f"{num}".encode()).hexdigest()
        if result == self.TARGET:
            print(f"\n\n\n\n{num}\n\n\n\n")
            self.num = num
            self.found = True
            

    def cleanup_unfinished_missions(self, username):
        '''
        Clean up unfinished missions for a disconnected client.

        Args:
            username (str): Username of the client whose missions are to be cleaned.
        '''
        try:
            conn = sqlite3.connect("demo.db")
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM missions WHERE username = ? AND done = 0", (username,))
            result = cursor.fetchone()

            if result:
                cursor.execute("DELETE FROM missions WHERE username = ? AND done = 0", (username,))
                conn.commit()
                self.queue.append(tuple(result[2].split('-')))
                print(f"Unfinished missions for {username} removed.")

        except sqlite3.Error as e:
            print(f"Database error while cleaning up missions: {e}")
        finally:
            conn.close()

    def run(self):
        '''
        Start accepting client connections and handle them in separate threads.
        '''
        while True:
            client_socket, addr = self.my_socket.accept()
            self.client_sockets.append(client_socket)
            print(f"Accepted connection from {addr}")
            client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_handler.start()

def main():
    '''
    Main entry point for the server program.
    '''
    s1 = server("0.0.0.0", 5555)
    s1.setup_database()
    s1.create_socket()
    s1.run()

if __name__ == "__main__":
    main()
