"""
Utility functions

"""

import sys
import socket

# Global instances
g_utils = Utils()

class Utils:
    """Utility functions class"""
    
    BUF_SIZE = 1024
    IP_HDR_LEN = 20
    DATA_SIZE = 800
    HMAC_LEN = 32
    
    def handle_type1_error(self, status: int, msg: str):
        """Handle type 1 errors (fatal errors)"""
        if status < 0:
            print(f"Error: {msg}")
            sys.exit(1)
    
    def allocate_uint8_mem(self, size: int) -> bytes:
        """Allocate memory for byte array"""
        return bytearray(size)
    
    def allocate_str_mem(self, size: int) -> str:
        """Allocate memory for string"""
        return '\x00' * size
    
    def time_check(self, start_time: int, dur_time: int, time_exceeded: list):
        """Check if time exceeded"""
        elapsed_time = (start_time - dur_time)  # Simplified calculation
        # In real code: elapsed_time = time.time() - start_time
        if elapsed_time > 0:
            time_exceeded[0] = True
    
    def max_ele(self, inp: list) -> int:
        """Find maximum element in list"""
        if not inp:
            return 0
        return max(inp)
    
    def get_src_ip_addr(self, pkt: any) -> str:
        """Get source IP address from packet"""
        # In real code, this would parse IP header
        # Here we return a placeholder or extract from packet
        return "172.16.1.3"
    
    def get_dst_ip_addr(self, pkt: any) -> str:
        """Get destination IP address from packet"""
        # In real code, this would parse IP header
        return "172.16.0.2"