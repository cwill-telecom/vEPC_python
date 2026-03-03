"""
UDP Client implementation

"""

import socket
import threading

class UdpClient:
    """UDP client class"""
    
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_addr = None
    
    def set_client(self, ip_addr: str):
        """Set client mode (binding to localhost)"""
        self.sock.bind(('127.0.0.1', 0))
    
    def set_server(self, ip_addr: str, port: int):
        """Set server mode (connecting to remote)"""
        self.sock.connect((ip_addr, port))
    
    def conn(self, ip_addr: str, port: int):
        """Connect to server"""
        self.sock.connect((ip_addr, port))
    
    def snd(self, pkt: any):
        """Send packet"""
        try:
            self.sock.sendto(pkt.data[pkt.data_ptr:pkt.len], self.server_addr)
        except (ConnectionRefusedError, OSError) as e:
            print(f"UDP send error: {e}")
    
    def rcv(self, pkt: any):
        """Receive packet"""
        try:
            data, addr = self.sock.recvfrom(1024)
            pkt.data = bytearray(data)
            pkt.data_ptr = 0
            pkt.len = len(data)
        except (ConnectionResetError, OSError) as e:
            pkt.len = -1