class Protocol:
    
    """
    all commands and params are seperated by |
    commands:
    client -> server: 
    REG: register, two parameters: username and password
    LOG: login, two parameters: username and password
    GETRANGE: get range of numbers to check, zero parameters
    FINISHEDRANGE: the client has finished the range of numbers to check, zero parameters
    FOUND: the client has found a number, one parameter: the number
    
    server -> client:
    RANGE: send range of numbers to check, two parameters: start and end
    
    
    """
    
    LENGTH_FIELD_SIZE = 8
    # קבוע במחלקה פרוטוקול שמגדיר ששדה האורך של הודעות הוא באורך 8
    
    @staticmethod
    def is_valid_msg(msg: str) -> bool:
        """
        """
    
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
    def get_msg(my_socket) -> tuple[bool, str]:
        """
        Extract message from protocol, without the length field
        If length field does not include a number, returns False, "Error"
        """
        
        msg_length = my_socket.recv(Protocol.LENGTH_FIELD_SIZE).decode(encoding="latin-1")
        try:
            msg_length = int(msg_length)
        except ValueError:
            return False, "Error"
        
        msg = my_socket.recv(msg_length)
        msg=msg.decode(encoding="latin-1")

        return True, msg
    
class client_protocol(Protocol):
    
    def __init__(self, socket) -> None:
        self.socket = socket
        
    def register(self, username, password):
        self.socket.send(f"REG|{username}|{password}".encode(encoding="latin-1"))
        
    
    def login(self, username, password):
        self.socket.send(f"LOG|{username}|{password}".encode(encoding="latin-1"))
    