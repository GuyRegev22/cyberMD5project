class Protocol:
    """
    Protocol for communication between client and server using a custom message format.
    
    All commands and parameters are separated by `|`.
    Commands:
    
    Client -> Server:
    - REG: Register a user, requires two parameters: username and password.
    - LOGIN: Log in a user, requires two parameters: username and password.
    - LOGOUT: Log out the current user, requires zero parameters.
    - GETRANGE: Request a range of numbers to check, requires zero parameters.
    - FINISHEDRANGE: Notify the server that the client has finished processing a range, requires zero parameters.
    - FOUND: Notify the server that the client found a number, requires one parameter: the number.

    Server -> Client:
    - RANGE: Send a range of numbers to the client, with two parameters: start and end.
    """

    LENGTH_FIELD_SIZE = 8  # Defines the fixed size for the message length field (8 characters).

    @staticmethod
    def send_msg(data, socket) -> None:
        """
        Sends a message over the socket with a prefixed length field.
        
        Args:
        - data (str): The message to send.
        - socket: The socket through which the message will be sent.
        """
        msg_length = str(len(data))
        zfill_length = msg_length.zfill(Protocol.LENGTH_FIELD_SIZE)
        msg = zfill_length.encode(encoding="latin-1") + data
        #print(msg)
        socket.send(msg)

    @staticmethod
    def get_msg(my_socket) -> str:
        """
        Receives a message from the socket, extracting and verifying its length.
        
        Args:
        - my_socket: The socket from which the message will be received.
        
        Returns:
        - str: The decoded message without the length field.
        - "Error" if the length field is invalid.
        """
        msg_length = my_socket.recv(Protocol.LENGTH_FIELD_SIZE).decode(encoding="latin-1")
        if msg_length == "":
            return ""
        while len(msg_length) < Protocol.LENGTH_FIELD_SIZE:
            msg_length += my_socket.recv(Protocol.LENGTH_FIELD_SIZE - len(msg_length)).decode(encoding="latin-1")
        try:
            msg_length = int(msg_length)
        except ValueError as e:            
            return f"Error {e}"

        msg = my_socket.recv(msg_length)
        while len(msg) < msg_length:
            msg += my_socket.recv(msg_length - len(msg))
        return msg.decode(encoding="latin-1")


class client_protocol(Protocol):
    """
    Client-side implementation of the Protocol, with methods for sending specific commands.
    """

    @staticmethod
    def register(cl_socket, username, password, phone_number) -> str:
        """
        Sends a registration request to the server.
        
        Args:
        - username (str): The username to register.
        - password (str): The password for the account.
        
        Returns:
        - str: The server's response.
        """
        client_protocol.send_msg(f"REG|{username}|{password}|{phone_number}".encode(encoding="latin-1"), cl_socket)
        return Protocol.get_msg(cl_socket)

    @staticmethod
    def logout(cl_socket) -> None:
        """
        Sends a logout request to the server.
        """
        client_protocol.send_msg("LOGOUT".encode(encoding="latin-1"), cl_socket)

    @staticmethod
    def login(cl_socket, username, password) -> bool:
        """
        Sends a login request to the server.
        
        Args:
        - username (str): The username to log in.
        - password (str): The password for the account.
        
        Returns:
        - bool: True if login is successful, False otherwise.
        """
        client_protocol.send_msg(f"LOGIN|{username}|{password}".encode(encoding="latin-1"), cl_socket)
        msg = client_protocol.get_msg(cl_socket)
        if msg.startswith("Error"):
            return False
        return msg == "Logged in successfully"

    @staticmethod
    def get_range(cl_socket, username) -> tuple[int, int, str] | bool | int:
        """
        Requests a range of numbers to check from the server.
        
        Returns:
        - tuple[int, int]: The start and end of the range if successful.
        - False if there is an error.
        """
        client_protocol.send_msg(f"GETRANGE|{username}".encode(encoding="latin-1"), cl_socket)
        msg = client_protocol.get_msg(cl_socket)
        if msg.startswith("FOUND"):
            return int(msg.split("|")[1])
        if msg.startswith("Error"):
            return False
        return (int(msg.split("|")[1]), int(msg.split("|")[2]), msg.split("|")[3])

    @staticmethod
    def send_found(cl_socket, number: int) -> None:
        """
        Notifies the server that the client has found a valid number.
        
        Args:
        - number (int): The found number.
        """
        client_protocol.send_msg(f"FOUND|{number}".encode(encoding="latin-1"), cl_socket)



class server_protocol(Protocol):
    """
    Server-side implementation of the Protocol, with methods for handling client requests.
    """

    @staticmethod
    def is_valid(msg: str) -> bool:
        """
        Validates the format of an incoming message.
        
        Args:
        - msg (str): The message to validate.
        
        Returns:
        - bool: True if the message is valid, False otherwise.
        """
        if msg == "":
            return True
        msg_split = msg.split("|")
        if msg_split[0] not in ["REG", "LOGIN", "LOGOUT", "GETRANGE", "FINISHEDRANGE", "FOUND", "CHECK"]:
            return False
        command = msg_split[0]
        match command:
            case "REG":
                return len(msg_split) == 4
            case "LOGIN":
                return len(msg_split) == 3
            case "LOGOUT" | "FINISHEDRANGE" | "CHECK":
                return len(msg_split) == 1
            case "FOUND" | "GETRANGE":
                return len(msg_split) == 2
        return True

    @staticmethod
    def get_request(cl_socket) -> list[str]:
        """
        Receives and validates a client request.
        
        Returns:
        - list[str]: The parsed request as a list of strings.
        """
        msg = server_protocol.get_msg(cl_socket)
        while not server_protocol.is_valid(msg):
            server_protocol.send_error(cl_socket=cl_socket)
            msg = server_protocol.get_msg(cl_socket)
        return msg.split("|")

    @staticmethod
    def send_error(cl_socket, error_msg: str=None) -> None:
        """
        Sends an error message to the client.
        """
        if error_msg is None:
            server_protocol.send_msg("Server Error".encode(encoding="latin-1"), cl_socket)
        else:
            server_protocol.send_msg(f"Server Error|{error_msg}".encode(encoding="latin-1"), cl_socket)

    @staticmethod
    def send_range(cl_socket, start: int, end: int, target: str) -> None:
        """
        Sends a range of numbers to the client.
        
        Args:
        - start (int): The start of the range.
        - end (int): The end of the range.
        - target (str): The hash of the target number.
        """
        server_protocol.send_msg(f"RANGE|{start}|{end}|{target}".encode(encoding="latin-1"), cl_socket)

    @staticmethod
    def send_login_success(cl_socket, success: bool) -> None:
        """
        Sends a login success or failure message to the client.
        
        Args:
        - success (bool): True if login is successful, False otherwise.
        """
        if success:
            server_protocol.send_msg("Logged in successfully".encode(encoding="latin-1"), cl_socket)
        else:
            server_protocol.send_error(cl_socket=cl_socket)

    @staticmethod
    def send_register_success(cl_socket, success: bool) -> None:
        """
        Sends a registration success or failure message to the client.
        
        Args:
        - success (bool): True if registration is successful, False otherwise.
        """
        if success:
            server_protocol.send_msg("Registered successfully".encode(encoding="latin-1"), cl_socket)
        else:
            server_protocol.send_error(cl_socket=cl_socket)

    @staticmethod
    def return_check(cl_socket, is_found: bool, num_found: int) -> None:
        """
        Sends the result of a "check if found" operation to the client.
        
        Args:
        - is_found (bool): True if a number was found, False otherwise.
        """
        if is_found:
            server_protocol.send_msg(f"FOUND|{num_found}".encode(encoding="latin-1"), cl_socket)
        else:
            server_protocol.send_msg("NOT FOUND".encode(encoding="latin-1"), cl_socket)
