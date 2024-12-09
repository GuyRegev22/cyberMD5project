import socket
import threading
import sqlite3
import hashlib
import protocol

class server:
    
    
    #initialize variables and start the server
    def __init__(self, IP, PORT):
        self.ip = IP
        self.port = PORT
        self.range = (0,0)
        self.queue = []
        self.client_sockets = []
        self.TARGET = "4b53a4fecb7377ad3d1a387d366d4a62"
        self.found = False

    def create_socket(self):
        self.my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.my_socket.bind((self.ip, self.port))
        self.my_socket.listen()
    
    def setup_database():
        conn = sqlite3.connect("demo.db")
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            username TEXT PRIMARY KEY,
                            password TEXT NOT NULL,
                            phone TEXT NOT NULL
                        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS missions (
                    username TEXT PRIMARY KEY,
                    range TEXT NOT NULL,
                    done BOOLEAN False
                )''')   #400-500
        conn.commit()
        conn.close()
        

    def handle_client (self, cl_socket):
        while True:
            parsed_req = protocol.server_protocol.get_request(cl_socket)
            # print(parsed_req)
            if parsed_req == b"" or parsed_req[0]: #ends client connection after client disconnected
                print("Client Disconnected")
                self.client_sockets.remove(cl_socket)
                cl_socket.close()
                break
            if parsed_req[0] == 'REG':
                retCode = self.register_user(username=parsed_req[1], password=parsed_req[2], phone=parsed_req[3])
                protocol.server_protocol.send_register_success(success=retCode, cl_socket=cl_socket)
            elif parsed_req[0] == 'LOGIN':
                retCode = self.authenticate_user(username=parsed_req[1], password=parsed_req[2])
                protocol.server_protocol.send_login_success(success=retCode, cl_socket=cl_socket)
            elif parsed_req[0] == 'GETRANGE': #somestatement -> request to give the calculations
                self.handle_calc_req(parsed_req, cl_socket) #should change it to client_SOCKET
            elif parsed_req[0] == 'FOUND': #valid if number is found
                self.valid_finding(parsed_req[1])
                
            protocol.server_protocol.return_check(is_found=self.found, cl_socket=cl_socket)

        self.client_socket.close()
    
    # Register user
    def register_user(self, username, password, phone):
        conn = sqlite3.connect("done.db")
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

    # Authenticate user
    def authenticate_user(self, username, password):
        conn = sqlite3.connect("demo.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        conn.close()
        return user is not None


    def handle_calc_req(self, parsed_req, sock): #i want to add a queue for the problematic ones and a static that is the highest number yet
        # Extract the username from the parsed request
        username = parsed_req.get("username")  # Adjust this based on your protocol parsing logic
        
        conn = sqlite3.connect("demo.db")
        cursor = conn.cursor()

        try:
            # Step 1: Mark the user's last mission as done
            cursor.execute("UPDATE missions SET done = 1 WHERE username = ? AND done = 0", (username,))
            conn.commit()

            # Step 2: Generate a new mission range
            if not self.queue:
                new_range_start = self.range[0] + 100
                new_range_end = new_range_start + 100
                self.range = (new_range_start, new_range_end)
            else:
                new_range_start, new_range_end = self.queue.pop()
            new_range = f"{new_range_start}-{new_range_end}"

            # Step 3: Insert the new mission into the database
            cursor.execute("INSERT INTO missions (username, range, done) VALUES (?, ?, 0)", (username, new_range))
            conn.commit()

            # Step 4: Send the new range to the client
            response = f"New mission assigned: {new_range}"
            protocol.server_protocol.send_range(sock, new_range_start, new_range_end, self.TARGET)

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            error_response = "Server error while processing mission request."
            protocol.server_protocol.send_error(sock, error_response)
        
        finally:
            conn.close()

    def valid_finding(self, num : int):
        result = hashlib.md5(f"{num}".encode()).hexdigest()
        if (result == self.target):
            self.found = True
                                


    #default run of the server
    def run(self):
        while True:
            client_socket, addr = self.my_socket.accept()
            self.client_sockets.append(client_socket)
            print(f"Accepted connection from {addr}")
            client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_handler.start()


def main():
    s1 = server("0.0.0.0", 80)
    s1.setup_database()
    s1.create_socket()
    s1.run()

if __name__ == "__main__":
    main()