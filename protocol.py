class Protocol:
    
    """
    all commands and params are seperated by |
    commands:
    client -> server: 
    REG: register, two parameters: username and password
    LOGIN: login, two parameters: username and password
    LOGOUT: logout, zero parameters
    GETRANGE: get range of numbers to check, zero parameters
    FINISHEDRANGE: the client has finished the range of numbers to check, zero parameters
    FOUND: the client has found a number, one parameter: the number
    
    server -> client:
    RANGE: send range of numbers to check, two parameters: start and end
    
    
    """
    
    LENGTH_FIELD_SIZE = 8
    # קבוע במחלקה פרוטוקול שמגדיר ששדה האורך של הודעות הוא באורך 8
    
    
    @staticmethod
    def send_msg(data: str, socket) -> None:
        """
        Create a valid protocol message, with length field\n
        The received data is string
        """

        msg_length: str = str(len(data))
        zfill_length: str = msg_length.zfill(Protocol.LENGTH_FIELD_SIZE)
        msg = zfill_length + data
        socket.send(msg.encode(encoding="latin-1"))

    @staticmethod
    def get_msg(my_socket) -> str:
        """
        Extract message from protocol, without the length field
        If length field does not include a number, returns False, "Error"
        """
        
        msg_length = my_socket.recv(Protocol.LENGTH_FIELD_SIZE).decode(encoding="latin-1")
        try:
            msg_length = int(msg_length)
        except ValueError:
            return "Error"
        
        msg = my_socket.recv(msg_length)
        msg=msg.decode(encoding="latin-1")

        return msg
    
class client_protocol(Protocol):
    
    def __init__(self, cl_socket) -> None:
        self.cl_socket = cl_socket
        
    # sends register message to server and returns the answer from the server
    def register(self, username, password):
        self.cl_socket.send(f"REG|{username}|{password}".encode(encoding="latin-1"))
        return self.get_msg(self.cl_socket)
    
    # sends logout message to the server
    def logout(self):
        self.cl_socket.send("LOGOUT".encode(encoding="latin-1"))
        
    # sends login message to server and returns the answer from the server
    def login(self, username, password):
        self.cl_socket.send(f"LOG|{username}|{password}".encode(encoding="latin-1"))
        return self.get_msg(self.cl_socket)
    
    def get_range(self) -> tuple[int, int] | bool:
        self.cl_socket.send("GETRANGE".encode(encoding="latin-1"))
        msg = self.get_msg(self.cl_socket)
        if msg == "Error":
            return False
        return tuple(map(int, msg.split("|")[1:]))

    def finished_range(self) -> None:
        self.cl_socket.send("FINISHEDRANGE".encode(encoding="latin-1"))
        
    def found(self, number: int) -> None:
        self.cl_socket.send(f"FOUND|{number}".encode(encoding="latin-1"))

class server_protocol(Protocol):
    
    def __init__(self, cl_socket) -> None:
        self.cl_socket = cl_socket
        
    def is_valid(self, msg: str) -> bool:
        msg_split = msg.split("|")
        if msg_split[0] not in ["REG", "LOGIN", "GETRANGE", "FINISHEDRANGE", "FOUND"]:
            return False
        command = msg_split[0]
        match command:
            case "REG":
                if len(msg_split) != 3:
                    return False
            case "LOGIN":
                if len(msg_split) != 3:
                    return False
            case "LOGOUT":
                if len(msg_split) != 1:
                    return False
            case "GETRANGE":
                if len(msg_split) != 1:
                    return False
            case "FINISHEDRANGE":
                if len(msg_split) != 1:
                    return False
            case "FOUND":
                if len(msg_split) != 2:
                    return False 
        return True
        
    def get_request(self) -> list[str]:
        msg = self.get_msg(self.cl_socket)
        while not self.is_valid(msg):
            msg = self.get_msg(self.cl_socket)
        return msg.split("|")
        
    