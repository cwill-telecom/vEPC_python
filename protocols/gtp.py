"""
GTP protocol implementation

"""

class Gtp:
    """GTP protocol header class"""
    
    def __init__(self):
        self.flags = 0
        self.msg_type = 0
        self.msg_len = 0
        self.teid = 0
        self.field_1 = 0
        self.field_2 = 0
        self.field_3 = 0
    
    def init(self, protocol: int, arg_msg_type: int, arg_msg_len: int, arg_teid: int):
        """Initialize GTP header"""
        self.msg_type = arg_msg_type
        self.msg_len = arg_msg_len
        self.teid = arg_teid
        
        if protocol == 1:  # GTPv1 (User plane)
            self.flags = 48
        elif protocol == 2:  # GTPv2 (Control plane)
            self.flags = 72 if teid > 0 else 64
        else:
            raise ValueError("gtp protocol error: gtp_init")
    
    def to_bytes(self) -> bytes:
        """Convert GTP header to bytes"""
        return bytes([
            self.flags,
            self.msg_type
        ]) + self.msg_len.to_bytes(2, 'big') + self.teid.to_bytes(4, 'big') + \
               self.field_1.to_bytes(2, 'big') + self.field_2.to_bytes(2, 'big') + \
               bytes([self.field_3])
    
    def from_bytes(self, data: bytes):
        """Parse GTP header from bytes"""
        self.flags = data[0]
        self.msg_type = data[1]
        self.msg_len = int.from_bytes(data[2:4], 'big')
        self.teid = int.from_bytes(data[4:8], 'big')
        self.field_1 = int.from_bytes(data[8:10], 'big')
        self.field_2 = int.from_bytes(data[10:12], 'big')
        self.field_3 = data[12]
    
    def __sizeof__(self):
        return 13  # GTP header length

# Constant
GTP_HDR_LEN = 13  # sizeof(Gtp)

# Protocol documentation as comments
"""
Protocol - gtpv1 (User plane)
	flags
		0 - 2 Version (GTPv1 - 1)
		3 Protocol type (GTP - 1)
		4 Reserved (0)
		5 Externsion Header flag (0)
		6 Sequence number (0)
		7 N-PDU Flag number (0)
	field_1
		Sequence number (0)
	field_2
		N-PDU number (0)
	field_3
		Next Extension Header type (0)

Protocol - gtpv2 (Control plane)
	flags
	 	0 - 2 Version (GTPv2 - 2)
	   3 Piggybacking (0)
		4 TEID (0 / 1)
		5 - 7 Spare (0)
	field_1 + field_2
		Sequence number (0)
	field_3
		Spare (0)
"""