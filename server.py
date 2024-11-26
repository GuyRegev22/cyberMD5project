import socket
import threading
import sqlite3

class server:
    
    
    #initialize variables and start the server
    def __init__(self, IP, PORT):
        self.ip = IP
        self.port = PORT

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
        

    def handle_client (self):
        while True:
            parsed_req = protocol.recv_request(self.client_socket)
            # print(parsed_req)
            if parsed_req == b"": #ends client connection after client disconnected
                print("Client Disconnected")
                self.client_socket.close()
                break
            if self.protocol.check_request(parsed_req):     #handles GET requests for now
                res = self.protocol.build_response(self.handle_response(parsed_req[0][0:2], parsed_req[2]))
                self.client_socket.send(res)
            else: #Unknown request or request
                self.protocol.build_response((self.STATUS_TABLE[500].encode(), self.protocol.CONTENT_TYPE["txt"], self.STATUS_TABLE[500]))
        
        self.client_socket.close()
    
    # Register user
    def register_user(username, password, phone):
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
    def authenticate_user(username, password):
        conn = sqlite3.connect("demo.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        conn.close()
        return user is not None

    def handle_calc_req ():
        pass

    #default run of the server
    def run(self):
        while True:
            client_socket, addr = self.my_socket.accept()
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