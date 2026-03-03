"""
SCTP Client implementation

"""

import socket
import struct

class SctpClient:
    """SCTP client class"""
    
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # SCTP uses TCP for simplicity here
    
    def conn(self, ip_addr: str, port: int):
        """Connect to server"""
        self.sock.connect((ip_addr, port))
    
    def snd(self, pkt: any):
        """Send packet"""
        try:
            self.sock.send(pkt.data[pkt.data_ptr:pkt.len])
        except (ConnectionRefusedError, OSError) as e:
            print(f"SCTP send error: {e}")
    
    def rcv(self, pkt: any):
        """Receive packet"""
        try:
            data = self.sock.recv(1024)
            pkt.data = bytearray(data)
            pkt.data_ptr = 0
            pkt.len = len(data)
        except (ConnectionResetError, OSError) as e:
            pkt.len = -1