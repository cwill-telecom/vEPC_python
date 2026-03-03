"""
Sink implementation for receiving traffic

"""

import socket
import threading

# Global configuration
g_pgw_sgi_ip_addr = "10.129.26.169"
g_sink_ip_addr = "10.129.26.169"
g_pgw_sgi_port = 8100
g_sink_port = 8500

class TrafficMonitor:
    """Traffic monitor for sink"""
    
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((g_sink_ip_addr, g_sink_port))
        self.conn_fd = self.sock.fileno()
    
    def snd(self, pkt: any):
        """Send packet to PGW"""
        try:
            self.sock.sendto(pkt.data[pkt.data_ptr:pkt.len], (g_pgw_sgi_ip_addr, g_pgw_sgi_port))
        except socket.error as e:
            print(f"Sink send error: {e}")
    
    def rcv(self, pkt: any):
        """Receive packet from PGW"""
        try:
            data, addr = self.sock.recvfrom(1024)
            pkt.data = bytearray(data)
            pkt.data_ptr = 0
            pkt.len = len(data)
        except socket.error as e:
            pkt.len = -1