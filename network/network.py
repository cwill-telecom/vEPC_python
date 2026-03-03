"""
Network utility functions

"""

import socket
import os
import struct
from typing import Dict, Tuple

# Global instances
g_nw = Network()

class Network:
    """Network utility class"""
    
    g_sock_addr_len = 16  # sizeof(sockaddr_in)
    g_reuse = 1
    g_freeport = 0
    
    g_timeout_lev1 = (5, 0)
    g_timeout_lev2 = (30, 0)
    g_timeout_lev3 = (60, 0)
    
    @staticmethod
    def set_inet_sock_addr(ip_addr: str, port: int, sock_addr: socket.SockAddrIn):
        """Set INET socket address"""
        try:
            sock_addr.sin_family = socket.AF_INET
            sock_addr.sin_port = socket.htons(port)
            sock_addr.sin_addr = socket.inet_aton(ip_addr)
        except socket.error as e:
            raise socket.error(f"inet_aton error: network_setinetsockaddr - {e}")
    
    @staticmethod
    def bind_sock(sock_fd: int, sock_addr: socket.SockAddrIn):
        """Bind socket"""
        try:
            os.bind(sock_fd, sock_addr)
        except OSError as e:
            raise OSError(f"Bind error: network_bindsock - {e}")
    
    @staticmethod
    def get_sock_addr(sock_fd: int, sock_addr: socket.SockAddrIn):
        """Get socket address"""
        try:
            os.getsockname(sock_fd, sock_addr)
        except OSError as e:
            raise OSError(f"Getsockname error: network_getsockaddr - {e}")
    
    @staticmethod
    def set_sock_reuse(sock_fd: int):
        """Set socket reuse option"""
        try:
            os.setsockopt(sock_fd, socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError as e:
            raise OSError(f"Setsockopt reuse error: network_setsockreuse - {e}")
    
    @staticmethod
    def set_rcv_timeout(sock_fd: int, level: int):
        """Set receive timeout"""
        timeout = (5, 0)  # Default 5 seconds
        if level == 1:
            timeout = Network.g_timeout_lev1
        elif level == 2:
            timeout = Network.g_timeout_lev2
        elif level == 3:
            timeout = Network.g_timeout_lev3
        
        try:
            os.setsockopt(sock_fd, socket.SOL_SOCKET, socket.SO_RCVTIMEO, 
                         struct.pack('ll', timeout[0], timeout[1]))
        except OSError as e:
            raise OSError(f"Setsockopt rcv timeout error: network_setrcvtimeout - {e}")
    
    @staticmethod
    def get_src_ip_addr(pkt) -> str:
        """Get source IP address from packet"""
        # Simplified implementation - in real code would parse IP header
        return "172.16.1.3"
    
    @staticmethod
    def get_dst_ip_addr(pkt) -> str:
        """Get destination IP address from packet"""
        # Simplified implementation - in real code would parse IP header
        return "172.16.0.2"
    
    @staticmethod
    def add_itf(itf_no: int, ip_addr_sp: str):
        """Add network interface"""
        cmd = f"sudo ip addr add {ip_addr_sp} dev eth0:{itf_no}"
        try:
            os.system(cmd)
        except Exception as e:
            print(f"Failed to add interface: {e}")
    
    @staticmethod
    def rem_itf(itf_no: int):
        """Remove network interface"""
        cmd = f"sudo ip link set eth0:{itf_no} down"
        try:
            os.system(cmd)
        except Exception as e:
            print(f"Failed to remove interface: {e}")
    
    @staticmethod
    def read_stream(conn_fd: int, buf: bytearray, length: int) -> int:
        """Read from stream"""
        ptr = 0
        remaining_bytes = length
        
        if conn_fd < 0 or length <= 0:
            return -1
        
        while remaining_bytes > 0:
            try:
                bytes_read = os.read(conn_fd, buf[ptr:ptr+remaining_bytes])
                if bytes_read <= 0:
                    return bytes_read
                ptr += bytes_read
                remaining_bytes -= bytes_read
            except OSError:
                return -1
        
        return length
    
    @staticmethod
    def write_stream(conn_fd: int, buf: bytearray, length: int) -> int:
        """Write to stream"""
        ptr = 0
        remaining_bytes = length
        
        if conn_fd < 0 or length <= 0:
            return -1
        
        while remaining_bytes > 0:
            try:
                bytes_written = os.write(conn_fd, buf[ptr:ptr+remaining_bytes])
                if bytes_written <= 0:
                    return bytes_written
                ptr += bytes_written
                remaining_bytes -= bytes_written
            except OSError:
                return -1
        
        return length
    
    @staticmethod
    def read_sctp_pkt(conn_fd: int, pkt) -> int:
        """Read SCTP packet"""
        retval = 0
        pkt_len = 0
        
        # Read packet length first
        length_data = bytearray(4)
        retval = Network.read_stream(conn_fd, length_data, 4)
        if retval > 0:
            pkt_len = struct.unpack('I', length_data)[0]
            
            pkt.clear_pkt()
            retval = Network.read_stream(conn_fd, pkt.data, pkt_len)
            pkt.data_ptr = 0
            pkt.len = retval
        
        return retval
    
    @staticmethod
    def write_sctp_pkt(conn_fd: int, pkt) -> int:
        """Write SCTP packet"""
        pkt.prepend_len()
        return Network.write_stream(conn_fd, pkt.data, pkt.len)