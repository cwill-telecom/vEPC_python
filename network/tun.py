"""
TUN/TAP interface implementation

"""

import os
import fcntl
import struct
import subprocess
from typing import Dict

# TUN/TAP constants
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca

class Tun:
    """TUN/TAP interface class"""
    
    def __init__(self):
        self.name = ""
        self.conn_fd = -1
    
    def conn(self, arg_name: str):
        """Connect to TUN interface"""
        self.init(arg_name)
        self.attach()
    
    def init(self, arg_name: str):
        """Initialize TUN interface"""
        self.name = arg_name
    
    def attach(self):
        """Attach to TUN interface"""
        try:
            # Open TUN device
            self.conn_fd = os.open('/dev/net/tun', os.O_RDWR)
            
            # Set up interface
            ifr = struct.pack('16sH', self.name.encode(), IFF_TUN | IFF_NO_PI)
            fcntl.ioctl(self.conn_fd, TUNSETIFF, ifr)
            
            # Get the actual interface name
            ifr = struct.unpack('16sH', fcntl.ioctl(self.conn_fd, TUNSETIFF, ifr))[0]
            self.name = ifr.decode().rstrip('\x00')
            
        except OSError as e:
            raise OSError(f"TUN attach error: {e}")
    
    def snd(self, pkt):
        """Send packet to TUN interface"""
        if self.conn_fd >= 0:
            try:
                os.write(self.conn_fd, pkt.data[pkt.data_ptr:pkt.len])
            except OSError as e:
                print(f"TUN write error: {e}")
    
    def rcv(self, pkt):
        """Receive packet from TUN interface"""
        if self.conn_fd >= 0:
            try:
                pkt.clear_pkt()
                nbytes = os.read(self.conn_fd, pkt.data)
                pkt.data_ptr = 0
                pkt.len = nbytes
            except OSError as e:
                print(f"TUN read error: {e}")
    
    def set_itf(self, name: str, ip_addr_sp: str):
        """Set interface name and IP address"""
        # Remove existing interface
        rmtun_cmd = f"sudo openvpn --rmtun --dev {name}"
        
        # Create new interface
        mktun_cmd = f"sudo openvpn --mktun --dev {name}"
        
        # Bring interface up
        itf_up_cmd = f"sudo ip link set {name} up"
        
        # Add IP address
        add_addr_cmd = f"sudo ip addr add {ip_addr_sp} dev {name}"
        
        # Set MTU
        set_mtu_cmd = f"sudo ifconfig {name} mtu 8000"
        
        try:
            subprocess.run(rmtun_cmd, shell=True, check=True)
            subprocess.run(mktun_cmd, shell=True, check=True)
            subprocess.run(itf_up_cmd, shell=True, check=True)
            subprocess.run(add_addr_cmd, shell=True, check=True)
            # subprocess.run(set_mtu_cmd, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to set interface: {e}")
    
    def __del__(self):
        """Cleanup"""
        if self.conn_fd >= 0:
            os.close(self.conn_fd)