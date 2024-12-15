import socket
import threading
import sqlite3
import hashlib
import protocol
'''
Need to add the logic of when a client disconnects
Maybe add a map to save cl_socket to a username
'''

class server:
    # Initialize variables and start the server
    def __init__(self, IP, PORT):
        self.ip = IP
        self.PORT = PORT
        self.range = (0, 0)
        self.queue = []
        self.client_sockets = []
        self.TARGET = "4b53a4fecb7377ad3d1a387d366d4a62"
        self.found = False

    def create_socket(self):
        self.my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.my_socket.bind((self.ip, self.PORT))
        self.my_socket.listen()
        print(f"Server is up and running on port:{self.PORT}")

    def setup_database(self):
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
        username = None  # Temporary storage for the session's username
        try:
            while True:
                parsed_req = protocol.server_protocol.get_request(cl_socket)
                if parsed_req == b"":  # Ends client connection after client disconnected
                    print("Client Disconnected")
                    self.client_sockets.remove(cl_socket)
                    cl_socket.close()
                    break
                if parsed_req[0] == 'REG':
                    retCode = self.register_user(username=parsed_req[1], password=parsed_req[2], phone=parsed_req[3])
                    if (retCode): username = parsed_req[1]
                    protocol.server_protocol.send_register_success(success=retCode, cl_socket=cl_socket)
                elif parsed_req[0] == 'LOGIN':
                    retCode = self.authenticate_user(username=parsed_req[1], password=parsed_req[2])
                    protocol.server_protocol.send_login_success(success=retCode, cl_socket=cl_socket)
                elif parsed_req[0] == 'GETRANGE':
                    self.handle_calc_req(parsed_req[1], cl_socket)
                elif parsed_req[0] == 'FOUND':
                    self.valid_finding(parsed_req[1])
                elif parsed_req[0] == 'LOGOUT':
                    print("Some client logged out!")
        except Exception as e:
            print(f"[*]Error: {e} [*]")
        finally:
            # Cleanup logic will use this username
            if username:
                self.cleanup_unfinished_missions(username)
            print("Client Disconnected")
            self.client_sockets.remove(cl_socket)
            cl_socket.close()

    def register_user(self, username, password, phone):
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
        conn = sqlite3.connect("demo.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        conn.close()
        return user is not None

    def handle_calc_req(self, username, sock):
        if self.found:
            protocol.server_protocol.return_check(is_found=self.found, cl_socket=sock)
            return

        conn = sqlite3.connect("demo.db")
        cursor = conn.cursor()

        try:
            # Mark previous missions as done
            cursor.execute("UPDATE missions SET done = 1 WHERE username = ? AND done = 0", (username,))
            conn.commit()

            # Generate new range
            if not self.queue:
                new_range_start = self.range[0] + 100
                new_range_end = new_range_start + 100
                self.range = (new_range_start, new_range_end)
            else:
                new_range_start, new_range_end = self.queue.pop()
            new_range = f"{new_range_start}-{new_range_end}"

            # Insert new mission
            cursor.execute("INSERT INTO missions (username, range, done) VALUES (?, ?, ?)", (username, new_range, 0))
            conn.commit()

            # Send new range to the client
            protocol.server_protocol.send_range(sock, new_range_start, new_range_end, self.TARGET)

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            protocol.server_protocol.send_error(sock, "Server error while processing mission request.")
        finally:
            conn.close()

    def valid_finding(self, num: int):
        result = hashlib.md5(f"{num}".encode()).hexdigest()
        if result == self.TARGET:
            self.found = True
    
    def cleanup_unfinished_missions(self, username):
        try:
            conn = sqlite3.connect("demo.db")
            cursor = conn.cursor()
            
            # Fetch the username associated with unfinished missions for this socket
            # Assuming the client sends its username when logging in or requesting ranges
            cursor.execute("SELECT * FROM missions WHERE done = 0")
            result = cursor.fetchone()
            
            if result:
                username = result[1]
                print(result)
                cursor.execute("DELETE FROM missions WHERE username = ? AND done = 0", (username,))
                conn.commit()
                print(f"Unfinished missions for {username} removed.")
                self.queue.append(tuple(result[1].split('-'))) #maybe 2 instead of 1
        except sqlite3.Error as e:
            print(f"Database error while cleaning up missions: {e}")
        finally:
            conn.close()

    def run(self):
        while True:
            client_socket, addr = self.my_socket.accept()
            self.client_sockets.append(client_socket)
            print(f"Accepted connection from {addr}")
            client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_handler.start()


def main():
    s1 = server("0.0.0.0", 5555)
    s1.setup_database()
    s1.create_socket()
    s1.run()


if __name__ == "__main__":
    main()
