"""
Packet Gateway (PGW) implementation

"""

import threading
import signal
from typing import Dict, List, Tuple
from diameter import Diameter
from gtp import Gtp
from network import Network
from packet import Packet
from s1ap import S1ap
from sync import g_sync
from udp_client import UdpClient
from udp_server import UdpServer
from utils import g_utils

# Global configuration
g_sgw_s5_ip_addr = "10.129.26.169"
g_pgw_s5_ip_addr = "10.129.26.169"
g_pgw_sgi_ip_addr = "10.129.26.169"
g_sink_ip_addr = "10.129.26.169"
g_sgw_s5_port = 7200
g_pgw_s5_port = 8000
g_pgw_sgi_port = 8100
g_sink_port = 8500
MAX_UE_COUNT = 1000

# Server thread counts
g_s5_server_threads_count = 0
g_sgi_server_threads_count = 0
g_s5_server_threads: List[threading.Thread] = []
g_sgi_server_threads: List[threading.Thread] = []

class UeContext:
    """UE context information for PGW"""
    
    def __init__(self):
        self.ip_addr = ""
        self.tai = 0
        self.apn_in_use = 0
        self.s5_uteid_ul = 0
        self.s5_uteid_dl = 0
        self.s5_cteid_ul = 0
        self.s5_cteid_dl = 0
        self.eps_bearer_id = 0
    
    def init(self, arg_ip_addr: str, arg_tai: int, arg_apn_in_use: int, 
             arg_eps_bearer_id: int, arg_s5_uteid_ul: int, arg_s5_uteid_dl: int, 
             arg_s5_cteid_ul: int, arg_s5_cteid_dl: int):
        self.ip_addr = arg_ip_addr
        self.tai = arg_tai
        self.apn_in_use = arg_apn_in_use
        self.eps_bearer_id = arg_eps_bearer_id
        self.s5_uteid_ul = arg_s5_uteid_ul
        self.s5_uteid_dl = arg_s5_uteid_dl
        self.s5_cteid_ul = arg_s5_cteid_ul
        self.s5_cteid_dl = arg_s5_cteid_dl

class Pgw:
    """Packet Gateway (PGW) implementation"""
    
    def __init__(self):
        self.s5_id = {}        # s5_cteid_ul -> imsi
        self.sgi_id = {}       # ue_ip_addr -> imsi
        self.ue_ctx = {}       # imsi -> UeContext
        self.ip_addrs = {}     # imsi -> ip_addr (write once, read always)
        
        self.s5id_mux = threading.Lock()
        self.sgiid_mux = threading.Lock()
        self.uectx_mux = threading.Lock()
        
        self.s5_server = UdpServer()
        self.sgi_server = UdpServer()
        
        # Initialize IP addresses
        self.set_ip_addrs()
    
    def clrstl(self):
        """Clear all data structures"""
        self.s5_id.clear()
        self.sgi_id.clear()
        self.ue_ctx.clear()
        self.ip_addrs.clear()
    
    def handle_create_session(self, src_sock_addr: Dict, pkt: Packet):
        """Handle create session request"""
        s5_cteid_dl = pkt.extract_item(int)
        imsi = pkt.extract_item(int)
        eps_bearer_id = pkt.extract_item(int)
        s5_uteid_dl = pkt.extract_item(int)
        apn_in_use = pkt.extract_item(int)
        tai = pkt.extract_item(int)
        
        s5_cteid_ul = s5_cteid_dl
        s5_uteid_ul = s5_cteid_dl
        ue_ip_addr = self.ip_addrs.get(imsi, "")
        
        self.update_itfid(5, s5_uteid_ul, "", imsi)
        self.update_itfid(0, 0, ue_ip_addr, imsi)
        
        g_sync.mlock(self.uectx_mux)
        self.ue_ctx[imsi] = UeContext()
        self.ue_ctx[imsi].init(ue_ip_addr, tai, apn_in_use, eps_bearer_id, 
                               s5_uteid_ul, s5_uteid_dl, s5_cteid_ul, s5_cteid_dl)
        g_sync.munlock(self.uectx_mux)
        
        pkt.clear_pkt()
        pkt.append_item(s5_cteid_ul)
        pkt.append_item(eps_bearer_id)
        pkt.append_item(s5_uteid_ul)
        pkt.append_item(ue_ip_addr)
        pkt.prepend_gtp_hdr(2, 1, pkt.len, s5_cteid_dl)
        self.s5_server.snd(src_sock_addr, pkt)
        print(f"pgw_handlecreatesession: create session response sent to mme: {imsi}")
    
    def handle_uplink_udata(self, pkt: Packet, sink_client: UdpClient):
        """Handle uplink user data"""
        pkt.truncate()
        sink_client.set_server(g_sink_ip_addr, g_sink_port)
        sink_client.snd(pkt)
        print(f"pgw_handleuplinkudata: uplink udata forwarded to sink: {pkt.len}")
    
    def handle_downlink_udata(self, pkt: Packet, sgw_s5_client: UdpClient):
        """Handle downlink user data"""
        ue_ip_addr = g_nw.get_dst_ip_addr(pkt)
        imsi = self.get_imsi(0, 0, ue_ip_addr)
        if imsi == 0:
            print(f"pgw_handledownlinkudata: zero imsi {pkt.gtp_hdr.teid} {pkt.len}: {imsi}")
            return
        
        res, s5_uteid_dl = self.get_downlink_info(imsi)
        if res:
            pkt.prepend_gtp_hdr(1, 3, pkt.len, s5_uteid_dl)
            sgw_s5_client.set_server(g_sgw_s5_ip_addr, g_sgw_s5_port)
            sgw_s5_client.snd(pkt)
            print(f"pgw_handledownlinkudata: downlink udata forwarded to sgw: {pkt.len}: {imsi}")
    
    def handle_detach(self, src_sock_addr: Dict, pkt: Packet):
        """Handle detach request"""
        res = True
        imsi = self.get_imsi(5, pkt.gtp_hdr.teid, "")
        if imsi == 0:
            print(f"pgw_handledetach: zero imsi {pkt.gtp_hdr.teid} {pkt.len}: {imsi}")
            g_utils.handle_type1_error(-1, "Zero imsi: pgw_handledetach")
        
        eps_bearer_id = pkt.extract_item(int)
        tai = pkt.extract_item(int)
        
        g_sync.mlock(self.uectx_mux)
        s5_cteid_ul = self.ue_ctx[imsi].s5_cteid_ul
        s5_cteid_dl = self.ue_ctx[imsi].s5_cteid_dl
        ue_ip_addr = self.ue_ctx[imsi].ip_addr
        g_sync.munlock(self.uectx_mux)
        
        pkt.clear_pkt()
        pkt.append_item(res)
        pkt.prepend_gtp_hdr(2, 4, pkt.len, s5_cteid_dl)
        self.s5_server.snd(src_sock_addr, pkt)
        print(f"pgw_handledetach: detach complete sent to sgw: {imsi}")
        
        self.rem_itfid(5, s5_cteid_ul, "")
        self.rem_itfid(0, 0, ue_ip_addr)
        self.rem_uectx(imsi)
        print(f"pgw_handledetach: detach successful: {imsi}")
    
    def set_ip_addrs(self):
        """Set IP addresses for UEs"""
        prefix = "172.16."
        subnet = 1
        host = 3
        
        for i in range(MAX_UE_COUNT):
            imsi = 119000000000 + i
            ip_addr = f"{prefix}{subnet}.{host}"
            self.ip_addrs[imsi] = ip_addr
            
            if host == 254:
                subnet += 1
                host = 3
            else:
                host += 1
    
    def update_itfid(self, itf_id_no: int, teid: int, ue_ip_addr: str, imsi: int):
        """Update interface ID mapping"""
        switch (itf_id_no):
            case 5:   # S5
                g_sync.mlock(self.s5id_mux)
                self.s5_id[teid] = imsi
                g_sync.munlock(self.s5id_mux)
                break
            
            case 0:   # SGI
                g_sync.mlock(self.sgiid_mux)
                self.sgi_id[ue_ip_addr] = imsi
                g_sync.munlock(self.sgiid_mux)
                break
            
            default:
                g_utils.handle_type1_error(-1, "incorrect itf_id_no: pgw_updateitfid")
    
    def get_imsi(self, itf_id_no: int, teid: int, ue_ip_addr: str) -> int:
        """Get IMSI from interface ID"""
        imsi = 0
        
        switch (itf_id_no):
            case 5:   # S5
                g_sync.mlock(self.s5id_mux)
                if teid in self.s5_id:
                    imsi = self.s5_id[teid]
                g_sync.munlock(self.s5id_mux)
                break
            
            case 0:   # SGI
                g_sync.mlock(self.sgiid_mux)
                if ue_ip_addr in self.sgi_id:
                    imsi = self.sgi_id[ue_ip_addr]
                g_sync.munlock(self.sgiid_mux)
                break
            
            default:
                g_utils.handle_type1_error(-1, "incorrect itf_id_no: pgw_getimsi")
        
        return imsi
    
    def get_downlink_info(self, imsi: int) -> Tuple[bool, int]:
        """Get downlink information for UE"""
        res = False
        s5_uteid_dl = 0
        
        g_sync.mlock(self.uectx_mux)
        if imsi in self.ue_ctx:
            res = True
            s5_uteid_dl = self.ue_ctx[imsi].s5_uteid_dl
        g_sync.munlock(self.uectx_mux)
        
        return res, s5_uteid_dl
    
    def rem_itfid(self, itf_id_no: int, teid: int, ue_ip_addr: str):
        """Remove interface ID mapping"""
        switch (itf_id_no):
            case 5:   # S5
                g_sync.mlock(self.s5id_mux)
                if teid in self.s5_id:
                    del self.s5_id[teid]
                g_sync.munlock(self.s5id_mux)
                break
            
            case 0:   # SGI
                g_sync.mlock(self.sgiid_mux)
                if ue_ip_addr in self.sgi_id:
                    del self.sgi_id[ue_ip_addr]
                g_sync.munlock(self.sgiid_mux)
                break
            
            default:
                g_utils.handle_type1_error(-1, "incorrect itf_id_no: pgw_remitfid")
    
    def rem_uectx(self, imsi: int):
        """Remove UE context"""
        g_sync.mlock(self.uectx_mux)
        if imsi in self.ue_ctx:
            del self.ue_ctx[imsi]
        g_sync.munlock(self.uectx_mux)

# Global PGW instance
g_pgw = Pgw()

def check_usage(argc: int):
    """Check command line usage"""
    if argc < 3:
        print("Usage: ./<pgw_server_exec> S5_SERVER_THREADS_COUNT SGI_SERVER_THREADS_COUNT")
        g_utils.handle_type1_error(-1, "Invalid usage error: pgwserver_checkusage")

def init(argv):
    """Initialize PGW server"""
    global g_s5_server_threads_count, g_sgi_server_threads_count
    global g_s5_server_threads, g_sgi_server_threads
    
    g_s5_server_threads_count = int(argv[1])
    g_sgi_server_threads_count = int(argv[2])
    
    g_s5_server_threads = [threading.Thread() for _ in range(g_s5_server_threads_count)]
    g_sgi_server_threads = [threading.Thread() for _ in range(g_sgi_server_threads_count)]
    
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

def run():
    """Run PGW server"""
    global g_s5_server_threads, g_sgi_server_threads
    
    # PGW S5 server
    print("PGW S5 server started")
    g_pgw.s5_server.run(g_pgw_s5_ip_addr, g_pgw_s5_port)
    for i in range(g_s5_server_threads_count):
        g_s5_server_threads[i] = threading.Thread(target=handle_s5_traffic)
        g_s5_server_threads[i].start()
    
    # PGW SGI server
    print("PGW SGI server started")
    g_pgw.sgi_server.run(g_pgw_sgi_ip_addr, g_pgw_sgi_port)
    for i in range(g_sgi_server_threads_count):
        g_sgi_server_threads[i] = threading.Thread(target=handle_sgi_traffic)
        g_sgi_server_threads[i].start()
    
    # Join all threads
    for thread in g_s5_server_threads:
        thread.join()
    
    for thread in g_sgi_server_threads:
        thread.join()

def handle_s5_traffic():
    """Handle S5 traffic"""
    sink_client = UdpClient()
    src_sock_addr = {}
    pkt = Packet()
    
    sink_client.set_client(g_pgw_sgi_ip_addr)
    while True:
        g_pgw.s5_server.rcv(src_sock_addr, pkt)
        pkt.extract_gtp_hdr()
        
        switch (pkt.gtp_hdr.msg_type):
            case 1:  # Create session
                print("pgwserver_handles5traffic: case 1: create session")
                g_pgw.handle_create_session(src_sock_addr, pkt)
                break
            
            case 2:  # Uplink userplane data
                print("pgwserver_handles5traffic: case 2: uplink udata")
                g_pgw.handle_uplink_udata(pkt, sink_client)
                break
            
            case 4:  # Detach
                print("pgwserver_handles5traffic: case 4: detach")
                g_pgw.handle_detach(src_sock_addr, pkt)
                break
            
            default:  # For error handling
                print("pgwserver_handles5traffic: default case:")

def handle_sgi_traffic():
    """Handle SGI traffic"""
    sgw_s5_client = UdpClient()
    src_sock_addr = {}
    pkt = Packet()
    
    sgw_s5_client.set_client(g_pgw_s5_ip_addr)
    while True:
        g_pgw.sgi_server.rcv(src_sock_addr, pkt)
        # Downlink userplane data
        print("pgwserver_handlesgitraffic: downlink udata")
        g_pgw.handle_downlink_udata(pkt, sgw_s5_client)

def main(argc: int, argv):
    """Main function for PGW server"""
    check_usage(argc)
    init(argv)
    run()
    return 0

if __name__ == "__main__":
    import sys
    main(len(sys.argv), sys.argv)