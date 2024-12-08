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

    def __init__(self, cl_socket) -> None:
        self.cl_socket = cl_socket

    def register(self, username, password):
        """
        Sends a registration request to the server.
        
        Args:
        - username (str): The username to register.
        - password (str): The password for the account.
        
        Returns:
        - str: The server's response.
        """
        self.cl_socket.send(f"REG|{username}|{password}".encode(encoding="latin-1"))
        return self.get_msg(self.cl_socket)

    def logout(self):
        """
        Sends a logout request to the server.
        """
        self.cl_socket.send("LOGOUT".encode(encoding="latin-1"))

    def login(self, username, password) -> bool:
        """
        Sends a login request to the server.
        
        Args:
        - username (str): The username to log in.
        - password (str): The password for the account.
        
        Returns:
        - bool: True if login is successful, False otherwise.
        """
        self.cl_socket.send(f"LOG|{username}|{password}".encode(encoding="latin-1"))
        msg = self.get_msg(self.cl_socket)
        if msg == "Error":
            return False
        return msg == "Logged in successfully"

    def get_range(self) -> tuple[int, int, str] | bool:
        """
        Requests a range of numbers to check from the server.
        
        Returns:
        - tuple[int, int]: The start and end of the range if successful.
        - False if there is an error.
        """
        self.cl_socket.send("GETRANGE".encode(encoding="latin-1"))
        msg = self.get_msg(self.cl_socket)
        if msg == "Error":
            return False
        return (int(msg.split("|")[1]), int(msg.split("|")[2]), msg.split("|")[3])

    def finished_range(self) -> None:
        """
        Notifies the server that the client has finished processing a range.
        """
        self.cl_socket.send("FINISHEDRANGE".encode(encoding="latin-1"))

    def send_found(self, number: int) -> None:
        """
        Notifies the server that the client has found a valid number.
        
        Args:
        - number (int): The found number.
        """
        self.cl_socket.send(f"FOUND|{number}".encode(encoding="latin-1"))

    def check_if_found(self) -> bool:
        """
        Checks with the server if a number has been found.
        
        Returns:
        - bool: True if the number was found, False otherwise.
        """
        self.cl_socket.send("CHECK".encode(encoding="latin-1"))
        msg = self.get_msg(self.cl_socket)
        return msg == "FOUND"


class server_protocol(Protocol):
    """
    Server-side implementation of the Protocol, with methods for handling client requests.
    """

    def __init__(self, cl_socket) -> None:
        self.cl_socket = cl_socket

    def is_valid(self, msg: str) -> bool:
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
                return len(msg_split) == 3
            case "LOGIN":
                return len(msg_split) == 3
            case "LOGOUT" | "GETRANGE" | "FINISHEDRANGE" | "CHECK":
                return len(msg_split) == 1
            case "FOUND":
                return len(msg_split) == 2
        return True

    def get_request(self) -> list[str]:
        """
        Receives and validates a client request.
        
        Returns:
        - list[str]: The parsed request as a list of strings.
        """
        msg = self.get_msg(self.cl_socket)
        while not self.is_valid(msg):
            msg = self.get_msg(self.cl_socket)
        return msg.split("|")

    def send_error(self) -> None:
        """
        Sends an error message to the client.
        """
        self.cl_socket.send("Error".encode(encoding="latin-1"))

    def send_range(self, start: int, end: int, target: str) -> None:
        """
        Sends a range of numbers to the client.
        
        Args:
        - start (int): The start of the range.
        - end (int): The end of the range.
        - target (str): The hash of the target number.
        """
        self.cl_socket.send(f"RANGE|{start}|{end}|{target}".encode(encoding="latin-1"))

    def send_login_success(self, success: bool) -> None:
        """
        Sends a login success or failure message to the client.
        
        Args:
        - success (bool): True if login is successful, False otherwise.
        """
        if success:
            self.cl_socket.send("Logged in successfully".encode(encoding="latin-1"))
        else:
            self.send_error()

    def send_register_success(self, success: bool) -> None:
        """
        Sends a registration success or failure message to the client.
        
        Args:
        - success (bool): True if registration is successful, False otherwise.
        """
        if success:
            self.cl_socket.send("Registered successfully".encode(encoding="latin-1"))
        else:
            self.send_error()

    def return_check(self, is_found: bool) -> None:
        """
        Sends the result of a "check if found" operation to the client.
        
        Args:
        - is_found (bool): True if a number was found, False otherwise.
        """
        if is_found:
            self.cl_socket.send("FOUND".encode(encoding="latin-1"))
        else:
            self.cl_socket.send("NOT FOUND".encode(encoding="latin-1"))
