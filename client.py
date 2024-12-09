import socket
import re
import hashlib
import multiprocessing
import threading
import time
from protocol import client_protocol

class client:
    server_ip = "127.0.0.1"
    server_port = 5555 
    connected = False
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def is_valid_username(self, username) -> bool:
        return (4 <= len(username) <= 16 and  #len between 4 and 16
                re.fullmatch(r"[a-zA-Z0-9]+", username) is not None)
    
    def is_valid_password(self, password) -> bool:
        return (6 <= len(password) <= 16 and #len between 6 and 16
                any(c.isupper() for c in password) and #one upper case
                any(c.isdigit() for c in password) and #one digit
                re.fullmatch(r"[a-zA-Z0-9]+", password) is not None) 


    def user_connection (self) : 
        username = ""
        while (not self.is_valid_username(username)):
            username = input("Enter a username: ").strip()
            if not self.is_valid_username(username):
                print("Invalid username. Spaces are forbidden use only lowercase letters and numbers.")
        
        password = ""
        while (not self.is_valid_password(password)):
            password = input("Enter a password: ").strip()
            if not self.is_valid_password(password):
                print("""Invalid password. At least one uppercase letter and one digit is requiered.
                      Password length must be between 6 and 16""")
                
        return username, password

    def register(self):
        username, password = self.user_connection()
        phone_number = input("Enter your phone number: ").strip() 
        while len(phone_number) != 10:
            print ("Invalid phone number") 
            phone_number = input("Enter your phone number: ").strip() 
        return client_protocol.register(self.client_socket, username, password, phone_number)



    def login (self):
        username, password = self.user_connection()

        return client_protocol.login(self.client_socket, username, password)




    def logout (self):
        return client_protocol.logout(self.client_socket)

    def handle_user_input (self, user_input):
        parts = user_input.strip().split(" ")
        if len(parts) != 1:
            print ("Invalid input")
            return ""
        command = parts[0]
        if command.lower() == "register":
            if self.connected:
                print ("You are already connected")
            else: 
                return self.register()
        elif command.lower() == "login":
            if self.connected:
                print ("You are already connected")
            else:
                return self.login()
        elif command.lower() == "logout":
            if self.connected:
                return self.logout()
            else:
                print ("Invalid command")
                return None

    def calc_hash(self, args):
        r"""
    Finds the number in the range [start, end] that produces the given MD5 hash.

    :param start: The starting number of the range (inclusive).
    :param end: The ending number of the range (inclusive).
    :param target_hash: The MD5 hash to match against (string).
    :return: The number that produces the target hash or None if no match is found.
    """
        
        start, end, target_hash = args
        for number in range(start, end + 1):
            # Convert the number to a string and encode it to bytes
            number_str = str(number).encode()
            # Compute the MD5 hash
            md5_hash = hashlib.md5(number_str).hexdigest()
            # Check if it matches the target hash
            if md5_hash == target_hash:
                return number  # Found a match
        return None  # No match found in the range

    def find_md5_match_multiprocessing(self, start, end, target_hash, num_processes=None):
        """
    Finds the number in the range [start, end] that produces the given MD5 hash using multiprocessing.
    
    :param start: The starting number of the range (inclusive).
    :param end: The ending number of the range (inclusive).
    :param target_hash: The MD5 hash to match against (string).
    :param num_processes: Number of processes to use. Defaults to the number of CPU cores.
    :return: The number that produces the target hash, or None if no match is found.
        """
        if num_processes is None:
            num_processes = multiprocessing.cpu_count()

        # Split the range into chunks for each process
        range_size = end - start + 1
        chunk_size = range_size // num_processes
        chunks = [
            (start + i * chunk_size, min(start + (i + 1) * chunk_size - 1, end), target_hash)
            for i in range(num_processes)
        ] #chunk is built as a tuple (start, end, target num) for each proccess
        # Adjust the last chunk to include all remaining numbers
        if chunks[-1][1] < end:
            chunks[-1] = (chunks[-1][0], end, target_hash)

        # Use multiprocessing.Pool to distribute the work
        with multiprocessing.Pool(processes=num_processes) as pool:
            results = pool.map(self.calc_hash(chunks))
            for result in results:
                if result is not None:
                    return result  # Return the first match immediately

        return None  # No match found


    def background_listener(self, stop_event):
        """
        Background task that runs in a separate thread and calls
        client_protocol_instance.check_if_found() every 2 seconds.
        """

        while not stop_event.is_set():
            if client_protocol.check_if_found(self.client_socket):
                print("Number found stopping search")
                self.not_found = False
                stop_event.set()
            time.sleep(2)  # Wait for 2 seconds


    
    def main(self, stop_event):
        
        try:
            self.client_socket.connect((self.server_ip, self.server_port))
        except socket.error as e:
            print(f"Failed to connect to the server: {e}")
        return
        
        
        try:
            while not stop_event.is_set():
                print("\n--- Client Menu ---")
                print("1. Register")
                print("2. Login")
                print("3. Logout")
                choice = input("Enter your choice: ").strip()
                while not self.handle_user_input(choice):
                    print("Error occured try again!")
                while (self.not_found):
                    ans = client_protocol.get_range(self.client_socket)
                    while not ans:
                        ans = client_protocol.get_range(self.client_socket)
                    start, end, target_hash = ans
                    result = self.find_md5_match_multiprocessing(start, end, target_hash)
                    if result is not None:
                        client_protocol.send_found(self.client_socket, result)
                    client_protocol.finished_range(self.client_socket)
                    if stop_event.is_set():
                        break
                stop_event.set()

        
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client.close()

    if __name__ == "__main__":
        # Start the background thread before the main function
        stop_event = threading.Event()
        background_thread = threading.Thread(target=background_listener, args=(stop_event,), daemon=True)
        background_thread.start()


        # Call the main function
        main(stop_event)


        background_thread.join()

