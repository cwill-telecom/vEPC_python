"""
Diameter protocol implementation

"""

class Diameter:
    """Diameter protocol header class"""
    
    def __init__(self):
        self.msg_type = 0
        self.msg_len = 0
    
    def init(self, arg_msg_type: int, arg_msg_len: int):
        """Initialize Diameter header"""
        self.msg_type = arg_msg_type
        self.msg_len = arg_msg_len
    
    def to_bytes(self) -> bytes:
        """Convert Diameter header to bytes"""
        return bytes([self.msg_type]) + self.msg_len.to_bytes(2, 'big')
    
    def from_bytes(self, data: bytes):
        """Parse Diameter header from bytes"""
        self.msg_type = data[0]
        self.msg_len = int.from_bytes(data[1:3], 'big')
    
    def __sizeof__(self):
        return 3  # 1 byte msg_type + 2 bytes msg_len

# Constant
DIAMETER_HDR_LEN = 3  # sizeof(Diameter)