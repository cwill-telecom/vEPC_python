"""
S1AP protocol implementation

"""

class S1ap:
    """S1AP protocol header class"""
    
    def __init__(self):
        self.msg_type = 0
        self.msg_len = 0
        self.enodeb_s1ap_ue_id = 0
        self.mme_s1ap_ue_id = 0
    
    def init(self, arg_msg_type: int, arg_msg_len: int, arg_enodeb_s1ap_ue_id: int, arg_mme_s1ap_ue_id: int):
        """Initialize S1AP header"""
        self.msg_type = arg_msg_type
        self.msg_len = arg_msg_len
        self.enodeb_s1ap_ue_id = arg_enodeb_s1ap_ue_id
        self.mme_s1ap_ue_id = arg_mme_s1ap_ue_id
    
    def to_bytes(self) -> bytes:
        """Convert S1AP header to bytes"""
        return bytes([self.msg_type]) + self.msg_len.to_bytes(2, 'big') + \
               self.enodeb_s1ap_ue_id.to_bytes(4, 'big') + self.mme_s1ap_ue_id.to_bytes(4, 'big')
    
    def from_bytes(self, data: bytes):
        """Parse S1AP header from bytes"""
        self.msg_type = data[0]
        self.msg_len = int.from_bytes(data[1:3], 'big')
        self.enodeb_s1ap_ue_id = int.from_bytes(data[3:7], 'big')
        self.mme_s1ap_ue_id = int.from_bytes(data[7:11], 'big')
    
    def __sizeof__(self):
        return 11  # sizeof(S1ap)

# Constant
S1AP_HDR_LEN = 11