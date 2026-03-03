"""
SCTP Server implementation

"""

import socket
import threading
import select

class SctpServer:
    """SCTP server class"""
    
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # SCTP uses TCP for simplicity here
        self.conn_fd = None
        self.running = False
    
    def run(self, ip_addr: str, port: int, threads_count: int = 1, callback=None):
        """Start server"""
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((ip_addr, port))
        self.sock.listen(5)
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
                client_sock, addr = self.sock.accept()
                client_sock.setblocking(0)
                client_conn_fd = client_sock.fileno()
                
                if callback:
                    callback(client_conn_fd, addr)
                
                client_sock.close()
            except socket.error as e:
                if self.running:
                    print(f"Accept error: {e}")
    
    def snd(self, conn_fd: int, pkt: any):
        """Send packet to client"""
        try:
            client_sock = socket.fromfd(conn_fd, socket.AF_INET, socket.SOCK_STREAM)
            client_sock.send(pkt.data[pkt.data_ptr:pkt.len])
            client_sock.close()
        except socket.error as e:
            print(f"SCTP send error: {e}")
    
    def rcv(self, conn_fd: int, pkt: any):
        """Receive packet"""
        # Forwarded from callback
        pass