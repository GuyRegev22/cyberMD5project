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
    def send_msg(data: str, socket) -> None:
        """
        Sends a message over the socket with a prefixed length field.
        
        Args:
        - data (str): The message to send.
        - socket: The socket through which the message will be sent.
        """
        msg_length: str = str(len(data))
        zfill_length: str = msg_length.zfill(Protocol.LENGTH_FIELD_SIZE)
        msg = zfill_length + data
        socket.send(msg.encode(encoding="latin-1"))

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
        try:
            msg_length = int(msg_length)
        except ValueError:
            return "Error"

        msg = my_socket.recv(msg_length)
        return msg.decode(encoding="latin-1")


class client_protocol(Protocol):
    """
    Client-side implementation of the Protocol, with methods for sending specific commands.
    """

    @staticmethod
    def register(username, password, phone_number, cl_socket) -> str:
        """
        Sends a registration request to the server.
        
        Args:
        - username (str): The username to register.
        - password (str): The password for the account.
        
        Returns:
        - str: The server's response.
        """
        cl_socket.send(f"REG|{username}|{password}|{phone_number}".encode(encoding="latin-1"))
        return Protocol.get_msg(cl_socket)

    @staticmethod
    def logout(cl_socket) -> None:
        """
        Sends a logout request to the server.
        """
        cl_socket.send("LOGOUT".encode(encoding="latin-1"))

    @staticmethod
    def login(username, password, cl_socket) -> bool:
        """
        Sends a login request to the server.
        
        Args:
        - username (str): The username to log in.
        - password (str): The password for the account.
        
        Returns:
        - bool: True if login is successful, False otherwise.
        """
        cl_socket.send(f"LOG|{username}|{password}".encode(encoding="latin-1"))
        msg = client_protocol.get_msg(cl_socket)
        if msg == "Error":
            return False
        return msg == "Logged in successfully"

    @staticmethod
    def get_range(cl_socket) -> tuple[int, int, str] | bool:
        """
        Requests a range of numbers to check from the server.
        
        Returns:
        - tuple[int, int]: The start and end of the range if successful.
        - False if there is an error.
        """
        cl_socket.send("GETRANGE".encode(encoding="latin-1"))
        msg = client_protocol.get_msg(cl_socket)
        if msg == "Error":
            return False
        return (int(msg.split("|")[1]), int(msg.split("|")[2]), msg.split("|")[3])

    @staticmethod
    def finished_range(cl_socket) -> None:
        """
        Notifies the server that the client has finished processing a range.
        """
        cl_socket.send("FINISHEDRANGE".encode(encoding="latin-1"))

    @staticmethod
    def send_found(number: int, cl_socket) -> None:
        """
        Notifies the server that the client has found a valid number.
        
        Args:
        - number (int): The found number.
        """
        cl_socket.send(f"FOUND|{number}".encode(encoding="latin-1"))

    @staticmethod
    def check_if_found(cl_socket) -> bool:
        """
        Checks with the server if a number has been found.
        
        Returns:
        - bool: True if the number was found, False otherwise.
        """
        cl_socket.send("CHECK".encode(encoding="latin-1"))
        msg = client_protocol.get_msg(cl_socket)
        return msg == "FOUND"


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
        msg_split = msg.split("|")
        if msg_split[0] not in ["REG", "LOGIN", "LOGOUT", "GETRANGE", "FINISHEDRANGE", "FOUND", "CHECK"]:
            return False
        command = msg_split[0]
        match command:
            case "REG":
                return len(msg_split) == 4
            case "LOGIN":
                return len(msg_split) == 3
            case "LOGOUT" | "GETRANGE" | "FINISHEDRANGE" | "CHECK":
                return len(msg_split) == 1
            case "FOUND":
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
            server_protocol.send_error()
            msg = server_protocol.get_msg(cl_socket)
        return msg.split("|")

    @staticmethod
    def send_error(cl_socket) -> None:
        """
        Sends an error message to the client.
        """
        cl_socket.send("Error".encode(encoding="latin-1"))

    @staticmethod
    def send_range(start: int, end: int, target: str, cl_socket) -> None:
        """
        Sends a range of numbers to the client.
        
        Args:
        - start (int): The start of the range.
        - end (int): The end of the range.
        - target (str): The hash of the target number.
        """
        cl_socket.send(f"RANGE|{start}|{end}|{target}".encode(encoding="latin-1"))

    @staticmethod
    def send_login_success(success: bool, cl_socket) -> None:
        """
        Sends a login success or failure message to the client.
        
        Args:
        - success (bool): True if login is successful, False otherwise.
        """
        if success:
            cl_socket.send("Logged in successfully".encode(encoding="latin-1"))
        else:
            server_protocol.send_error()

    @staticmethod
    def send_register_success(success: bool, cl_socket) -> None:
        """
        Sends a registration success or failure message to the client.
        
        Args:
        - success (bool): True if registration is successful, False otherwise.
        """
        if success:
            cl_socket.send("Registered successfully".encode(encoding="latin-1"))
        else:
            server_protocol.send_error()

    @staticmethod
    def return_check(is_found: bool, cl_socket) -> None:
        """
        Sends the result of a "check if found" operation to the client.
        
        Args:
        - is_found (bool): True if a number was found, False otherwise.
        """
        if is_found:
            cl_socket.send("FOUND".encode(encoding="latin-1"))
        else:
            cl_socket.send("NOT FOUND".encode(encoding="latin-1"))
