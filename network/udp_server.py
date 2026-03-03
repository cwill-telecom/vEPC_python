"""
UDP Server implementation

"""

import socket
import threading

class UdpServer:
    """UDP server class"""
    
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.conn_fd = None
        self.running = False
    
    def run(self, ip_addr: str, port: int, threads_count: int = 1, callback=None):
        """Start server"""
        self.sock.bind((ip_addr, port))
        self.conn_fd = self.sock.fileno()
        self.running = True
        
        # Start threads
        for i in range(threads_count):
            thread = threading.Thread(target=self._handle_connection, args=(callback,))
            thread.start()
    
    def _handle_connection(self, callback):
        """Handle incoming connections in separate thread"""
        while self.running:
            try:
                data, addr = self.sock.recvfrom(1024)
                src_sock_addr = addr
                
                if callback:
                    pkt = Packet()
                    pkt.data = bytearray(data)
                    pkt.data_ptr = 0
                    pkt.len = len(data)
                    callback(src_sock_addr, pkt)
            except socket.error as e:
                if self.running:
                    print(f"UDP server error: {e}")
    
    def snd(self, src_sock_addr: socket.SockAddrIn, pkt: any):
        """Send packet to source address"""
        try:
            self.sock.sendto(pkt.data[pkt.data_ptr:pkt.len], src_sock_addr)
        except socket.error as e:
            print(f"UDP sendto error: {e}")
    
    def rcv(self, src_sock_addr: Dict, pkt: any):
        """Receive packet"""
        # Forwarded from callback
        pass