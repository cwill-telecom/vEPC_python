"""
Serving Gateway (SGW) implementation

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
g_sgw_s11_ip_addr = "10.129.26.169"
g_sgw_s1_ip_addr = "10.129.26.169"
g_sgw_s5_ip_addr = "10.129.26.169"
g_sgw_s11_port = 7000
g_sgw_s1_port = 7100
g_sgw_s5_port = 7200

# Server thread counts
g_s11_server_threads_count = 0
g_s1_server_threads_count = 0
g_s5_server_threads_count = 0
g_s11_server_threads: List[threading.Thread] = []
g_s1_server_threads: List[threading.Thread] = []
g_s5_server_threads: List[threading.Thread] = []

class UeContext:
    """UE context information for SGW"""
    
    def __init__(self):
        self.tai = 0
        self.apn_in_use = 0
        self.eps_bearer_id = 0
        self.s1_uteid_ul = 0
        self.s1_uteid_dl = 0
        self.s5_uteid_ul = 0
        self.s5_uteid_dl = 0
        self.s11_cteid_mme = 0
        self.s11_cteid_sgw = 0
        self.s5_cteid_ul = 0
        self.s5_cteid_dl = 0
        self.pgw_s5_ip_addr = ""
        self.pgw_s5_port = 0
        self.enodeb_ip_addr = ""
        self.enodeb_port = 0
    
    def init(self, arg_tai: int, arg_apn_in_use: int, arg_eps_bearer_id: int, 
             arg_s1_uteid_ul: int, arg_s5_uteid_dl: int, arg_s11_cteid_mme: int, 
             arg_s11_cteid_sgw: int, arg_s5_cteid_dl: int, 
             arg_pgw_s5_ip_addr: str, arg_pgw_s5_port: int):
        self.tai = arg_tai
        self.apn_in_use = arg_apn_in_use
        self.eps_bearer_id = arg_eps_bearer_id
        self.s1_uteid_ul = arg_s1_uteid_ul
        self.s5_uteid_dl = arg_s5_uteid_dl
        self.s11_cteid_mme = arg_s11_cteid_mme
        self.s11_cteid_sgw = arg_s11_cteid_sgw
        self.s5_cteid_dl = arg_s5_cteid_dl
        self.pgw_s5_ip_addr = arg_pgw_s5_ip_addr
        self.pgw_s5_port = arg_pgw_s5_port

class Sgw:
    """Serving Gateway (SGW) implementation"""
    
    def __init__(self):
        self.s11_id = {}      # s11_cteid_sgw -> imsi
        self.s1_id = {}       # s1_uteid_ul -> imsi
        self.s5_id = {}       # s5_uteid_dl -> imsi
        self.ue_ctx = {}      # imsi -> UeContext
        self.ho_ue_ctx = {}   # imsi -> UeContext (handover context)
        
        self.s11id_mux = threading.Lock()
        self.s1id_mux = threading.Lock()
        self.s5id_mux = threading.Lock()
        self.uectx_mux = threading.Lock()
        
        self.s11_server = UdpServer()
        self.s1_server = UdpServer()
        self.s5_server = UdpServer()
    
    def clrstl(self):
        """Clear all data structures"""
        self.s11_id.clear()
        self.s1_id.clear()
        self.s5_id.clear()
        self.ue_ctx.clear()
        self.ho_ue_ctx.clear()
    
    def handle_create_session(self, src_sock_addr: Dict, pkt: Packet, pgw_s5_client: UdpClient):
        """Handle create session request"""
        s1_uteid_ul = 0
        s5_uteid_ul = 0
        s5_uteid_dl = 0
        s11_cteid_mme = pkt.extract_item(int)
        s11_cteid_sgw = s11_cteid_mme
        imsi = pkt.extract_item(int)
        eps_bearer_id = pkt.extract_item(int)
        pgw_s5_ip_addr = pkt.extract_item(str)
        pgw_s5_port = pkt.extract_item(int)
        apn_in_use = pkt.extract_item(int)
        tai = pkt.extract_item(int)
        
        s1_uteid_ul = s11_cteid_mme
        s5_uteid_dl = s11_cteid_mme
        s11_cteid_sgw = s11_cteid_mme
        s5_cteid_dl = s11_cteid_mme
        
        self.update_itfid(11, s11_cteid_sgw, imsi)
        self.update_itfid(1, s1_uteid_ul, imsi)
        self.update_itfid(5, s5_uteid_dl, imsi)
        
        g_sync.mlock(self.uectx_mux)
        self.ue_ctx[imsi] = UeContext()
        self.ue_ctx[imsi].init(tai, apn_in_use, eps_bearer_id, s1_uteid_ul, 
                               s5_uteid_dl, s11_cteid_mme, s11_cteid_sgw, 
                               s5_cteid_dl, pgw_s5_ip_addr, pgw_s5_port)
        self.ue_ctx[imsi].tai = tai
        g_sync.munlock(self.uectx_mux)
        
        print(f"sgw_handlecreatesession: ue entry added: {imsi}")
        
        pgw_s5_client.set_server(pgw_s5_ip_addr, pgw_s5_port)
        pkt.clear_pkt()
        pkt.append_item(s5_cteid_dl)
        pkt.append_item(imsi)
        pkt.append_item(eps_bearer_id)
        pkt.append_item(s5_uteid_dl)
        pkt.append_item(apn_in_use)
        pkt.append_item(tai)
        pkt.prepend_gtp_hdr(2, 1, pkt.len, 0)
        pgw_s5_client.snd(pkt)
        print(f"sgw_handlecreatesession: create session request sent to pgw: {imsi}")
        
        pgw_s5_client.rcv(pkt)
        print(f"sgw_handlecreatesession: create session response received from pgw: {imsi}")
        
        pkt.extract_gtp_hdr()
        s5_cteid_ul = pkt.extract_item(int)
        eps_bearer_id = pkt.extract_item(int)
        s5_uteid_ul = pkt.extract_item(int)
        ue_ip_addr = pkt.extract_item(str)
        
        g_sync.mlock(self.uectx_mux)
        self.ue_ctx[imsi].s5_uteid_ul = s5_uteid_ul
        self.ue_ctx[imsi].s5_cteid_ul = s5_cteid_ul
        g_sync.munlock(self.uectx_mux)
        
        pkt.clear_pkt()
        pkt.append_item(s11_cteid_sgw)
        pkt.append_item(ue_ip_addr)
        pkt.append_item(s1_uteid_ul)
        pkt.append_item(s5_uteid_ul)
        pkt.append_item(s5_uteid_dl)
        pkt.prepend_gtp_hdr(2, 1, pkt.len, s11_cteid_mme)
        self.s11_server.snd(src_sock_addr, pkt)
        print(f"sgw_handlecreatesession: create session response sent to mme: {imsi}")
    
    def handle_modify_bearer(self, src_sock_addr: Dict, pkt: Packet):
        """Handle modify bearer request"""
        imsi = self.get_imsi(11, pkt.gtp_hdr.teid)
        if imsi == 0:
            print(f"sgw_handlemodifybearer: zero imsi {pkt.gtp_hdr.teid} {pkt.len}: {imsi}")
            g_utils.handle_type1_error(-1, "Zero imsi: sgw_handlemodifybearer")
        
        eps_bearer_id = pkt.extract_item(int)
        s1_uteid_dl = pkt.extract_item(int)
        enodeb_ip_addr = pkt.extract_item(str)
        enodeb_port = pkt.extract_item(int)
        
        g_sync.mlock(self.uectx_mux)
        self.ue_ctx[imsi].s1_uteid_dl = s1_uteid_dl
        self.ue_ctx[imsi].enodeb_ip_addr = enodeb_ip_addr
        self.ue_ctx[imsi].enodeb_port = enodeb_port
        s11_cteid_mme = self.ue_ctx[imsi].s11_cteid_mme
        g_sync.munlock(self.uectx_mux)
        
        res = True
        pkt.clear_pkt()
        pkt.append_item(res)
        pkt.prepend_gtp_hdr(2, 2, pkt.len, s11_cteid_mme)
        self.s11_server.snd(src_sock_addr, pkt)
        print(f"sgw_handlemodifybearer: modify bearer response sent to mme: {imsi}")
    
    def handle_uplink_udata(self, pkt: Packet, pgw_s5_client: UdpClient):
        """Handle uplink user data"""
        imsi = self.get_imsi(1, pkt.gtp_hdr.teid)
        if imsi == 0:
            print(f"sgw_handleuplinkudata: zero imsi {pkt.gtp_hdr.teid} {pkt.len}: {imsi}")
            return
        
        res, s5_uteid_ul, pgw_s5_ip_addr, pgw_s5_port = self.get_uplink_info(imsi)
        if res:
            pkt.truncate()
            pkt.prepend_gtp_hdr(1, 2, pkt.len, s5_uteid_ul)
            pgw_s5_client.set_server(pgw_s5_ip_addr, pgw_s5_port)
            pgw_s5_client.snd(pkt)
            print(f"sgw_handleuplinkudata: uplink udata forwarded to pgw: {pkt.len}: {imsi}")
    
    def handle_downlink_udata(self, pkt: Packet, enodeb_client: UdpClient):
        """Handle downlink user data"""
        imsi = self.get_imsi(5, pkt.gtp_hdr.teid)
        if imsi == 0:
            print(f"sgw_handledownlinkudata: zero imsi {pkt.gtp_hdr.teid} {pkt.len}: {imsi}")
            return
        
        res, s1_uteid_dl, enodeb_ip_addr, enodeb_port = self.get_downlink_info(imsi)
        if res:
            pkt.truncate()
            pkt.prepend_gtp_hdr(1, 2, pkt.len, s1_uteid_dl)
            print(f"sgw_handledownlinkudata: **{enodeb_ip_addr}** {enodeb_port} {s1_uteid_dl}: {imsi}")
            enodeb_client.set_server(enodeb_ip_addr, enodeb_port)
            enodeb_client.snd(pkt)
            print(f"sgw_handledownlinkudata: downlink udata forwarded to enodeb: {pkt.len}: {imsi}")
    
    def handle_indirect_tunnel_setup(self, src_sock_addr: Dict, pkt: Packet):
        """Handle indirect tunnel setup for handover"""
        imsi = self.get_imsi(11, pkt.gtp_hdr.teid)
        s1_uteid_dl = pkt.extract_item(int)
        s1_uteid_ul = 0
        s11_cteid_mme = 0
        res = False
        
        g_sync.mlock(self.uectx_mux)
        self.ho_ue_ctx[imsi] = UeContext()
        self.ho_ue_ctx[imsi].s1_uteid_dl = s1_uteid_dl
        s11_cteid_mme = self.ue_ctx[imsi].s11_cteid_mme
        g_sync.munlock(self.uectx_mux)
        
        res = True
        s1_uteid_ul = s11_cteid_mme + 1
        
        self.update_itfid(1, s1_uteid_ul, imsi)
        pkt.clear_pkt()
        pkt.append_item(res)
        pkt.append_item(s1_uteid_ul)
        pkt.prepend_gtp_hdr(2, 4, pkt.len, s11_cteid_mme)
        self.s11_server.snd(src_sock_addr, pkt)
        print("indirect tunnel set up done at sgw")
    
    def handle_handover_completion(self, src_sock_addr: Dict, pkt: Packet):
        """Handle handover completion"""
        imsi = self.get_imsi(11, pkt.gtp_hdr.teid)
        s1_uteid_dl = 0
        s1_uteid_ul = 0
        s11_cteid_mme = 0
        res = False
        
        g_sync.mlock(self.uectx_mux)
        self.ue_ctx[imsi].s1_uteid_dl = self.ho_ue_ctx[imsi].s1_uteid_dl
        s11_cteid_mme = self.ue_ctx[imsi].s11_cteid_mme
        g_sync.munlock(self.uectx_mux)
        
        res = True
        
        # Remove from handover entry
        if imsi in self.ho_ue_ctx:
            del self.ho_ue_ctx[imsi]
        
        pkt.clear_pkt()
        pkt.append_item(res)
        pkt.prepend_gtp_hdr(2, 5, pkt.len, s11_cteid_mme)
        self.s11_server.snd(src_sock_addr, pkt)
        print("switched downlink for the particular UE, removed entry from HO context")
    
    def handle_indirect_tunnel_teardown_(self, src_sock_addr: Dict, pkt: Packet):
        """Handle indirect tunnel teardown"""
        imsi = self.get_imsi(11, pkt.gtp_hdr.teid)
        s1_uteid_ul_indirect = 0
        s11_cteid_mme = 0
        res = False
        
        s11_cteid_mme = self.ue_ctx[imsi].s11_cteid_mme
        s1_uteid_ul_indirect = pkt.extract_item(int)
        
        self.rem_itfid(1, s1_uteid_ul_indirect)
        
        res = True
        pkt.clear_pkt()
        pkt.append_item(res)
        pkt.prepend_gtp_hdr(2, 6, pkt.len, s11_cteid_mme)
        self.s11_server.snd(src_sock_addr, pkt)
        print("teardown of indirect uplink teid complete at sgw")
    
    def handle_detach(self, src_sock_addr: Dict, pkt: Packet, pgw_s5_client: UdpClient):
        """Handle detach request"""
        imsi = self.get_imsi(11, pkt.gtp_hdr.teid)
        if imsi == 0:
            print(f"sgw_handledetach: {pkt.gtp_hdr.teid} {pkt.len}: {imsi}")
            g_utils.handle_type1_error(-1, "Zero imsi: sgw_handledetach")
        
        eps_bearer_id = pkt.extract_item(int)
        tai = pkt.extract_item(int)
        
        g_sync.mlock(self.uectx_mux)
        if imsi not in self.ue_ctx:
            print(f"sgw_handledetach: no uectx: {imsi}")
            g_utils.handle_type1_error(-1, "No uectx: sgw_handledetach")
        
        pgw_s5_ip_addr = self.ue_ctx[imsi].pgw_s5_ip_addr
        pgw_s5_port = self.ue_ctx[imsi].pgw_s5_port
        s5_cteid_ul = self.ue_ctx[imsi].s5_cteid_ul
        s11_cteid_mme = self.ue_ctx[imsi].s11_cteid_mme
        s11_cteid_sgw = self.ue_ctx[imsi].s11_cteid_sgw
        s1_uteid_ul = self.ue_ctx[imsi].s1_uteid_ul
        s5_uteid_dl = self.ue_ctx[imsi].s5_uteid_dl
        g_sync.munlock(self.uectx_mux)
        
        pgw_s5_client.set_server(pgw_s5_ip_addr, pgw_s5_port)
        pkt.clear_pkt()
        pkt.append_item(eps_bearer_id)
        pkt.append_item(tai)
        pkt.prepend_gtp_hdr(2, 4, pkt.len, s5_cteid_ul)
        pgw_s5_client.snd(pkt)
        print(f"sgw_handledetach: detach request sent to pgw: {imsi}")
        
        pgw_s5_client.rcv(pkt)
        print(f"sgw_handledetach: detach response received from pgw: {imsi}")
        
        pkt.extract_gtp_hdr()
        res = pkt.extract_item(bool)
        if not res:
            print(f"sgw_handledetach: pgw detach failure: {imsi}")
            return
        
        pkt.clear_pkt()
        pkt.append_item(res)
        pkt.prepend_gtp_hdr(2, 3, pkt.len, s11_cteid_mme)
        self.s11_server.snd(src_sock_addr, pkt)
        print(f"sgw_handledetach: detach response sent to mme: {imsi}")
        
        self.rem_itfid(11, s11_cteid_sgw)
        self.rem_itfid(1, s1_uteid_ul)
        self.rem_itfid(5, s5_uteid_dl)
        self.rem_uectx(imsi)
        print(f"sgw_handledetach: ue entry removed: {imsi}")
        print(f"sgw_handledetach: detach successful: {imsi}")
    
    def update_itfid(self, itf_id_no: int, teid: int, imsi: int):
        """Update interface ID mapping"""
        switch (itf_id_no):
            case 11:  # S11
                g_sync.mlock(self.s11id_mux)
                self.s11_id[teid] = imsi
                g_sync.munlock(self.s11id_mux)
                break
            
            case 1:   # S1
                g_sync.mlock(self.s1id_mux)
                self.s1_id[teid] = imsi
                g_sync.munlock(self.s1id_mux)
                break
            
            case 5:   # S5
                g_sync.mlock(self.s5id_mux)
                self.s5_id[teid] = imsi
                g_sync.munlock(self.s5id_mux)
                break
            
            default:
                g_utils.handle_type1_error(-1, "incorrect itf_id_no: sgw_updateitfid")
    
    def get_imsi(self, itf_id_no: int, teid: int) -> int:
        """Get IMSI from interface ID"""
        imsi = 0
        
        switch (itf_id_no):
            case 11:  # S11
                g_sync.mlock(self.s11id_mux)
                if teid in self.s11_id:
                    imsi = self.s11_id[teid]
                g_sync.munlock(self.s11id_mux)
                break
            
            case 1:   # S1
                g_sync.mlock(self.s1id_mux)
                if teid in self.s1_id:
                    imsi = self.s1_id[teid]
                g_sync.munlock(self.s1id_mux)
                break
            
            case 5:   # S5
                g_sync.mlock(self.s5id_mux)
                if teid in self.s5_id:
                    imsi = self.s5_id[teid]
                g_sync.munlock(self.s5id_mux)
                break
            
            default:
                g_utils.handle_type1_error(-1, "incorrect itf_id_no: sgw_getimsi")
        
        return imsi
    
    def get_uplink_info(self, imsi: int) -> Tuple[bool, int, str, int]:
        """Get uplink information for UE"""
        res = False
        s5_uteid_ul = 0
        pgw_s5_ip_addr = ""
        pgw_s5_port = 0
        
        g_sync.mlock(self.uectx_mux)
        if imsi in self.ue_ctx:
            res = True
            s5_uteid_ul = self.ue_ctx[imsi].s5_uteid_ul
            pgw_s5_ip_addr = self.ue_ctx[imsi].pgw_s5_ip_addr
            pgw_s5_port = self.ue_ctx[imsi].pgw_s5_port
        g_sync.munlock(self.uectx_mux)
        
        return res, s5_uteid_ul, pgw_s5_ip_addr, pgw_s5_port
    
    def get_downlink_info(self, imsi: int) -> Tuple[bool, int, str, int]:
        """Get downlink information for UE"""
        res = False
        s1_uteid_dl = 0
        enodeb_ip_addr = ""
        enodeb_port = 0
        
        g_sync.mlock(self.uectx_mux)
        if imsi in self.ue_ctx and self.ue_ctx[imsi].enodeb_port != 0:
            res = True
            s1_uteid_dl = self.ue_ctx[imsi].s1_uteid_dl
            enodeb_ip_addr = self.ue_ctx[imsi].enodeb_ip_addr
            enodeb_port = self.ue_ctx[imsi].enodeb_port
        g_sync.munlock(self.uectx_mux)
        
        return res, s1_uteid_dl, enodeb_ip_addr, enodeb_port
    
    def rem_itfid(self, itf_id_no: int, teid: int):
        """Remove interface ID mapping"""
        switch (itf_id_no):
            case 11:  # S11
                g_sync.mlock(self.s11id_mux)
                if teid in self.s11_id:
                    del self.s11_id[teid]
                g_sync.munlock(self.s11id_mux)
                break
            
            case 1:   # S1
                g_sync.mlock(self.s1id_mux)
                if teid in self.s1_id:
                    del self.s1_id[teid]
                g_sync.munlock(self.s1id_mux)
                break
            
            case 5:   # S5
                g_sync.mlock(self.s5id_mux)
                if teid in self.s5_id:
                    del self.s5_id[teid]
                g_sync.munlock(self.s5id_mux)
                break
            
            default:
                g_utils.handle_type1_error(-1, "incorrect itf_id_no: sgw_remitfid")
    
    def rem_uectx(self, imsi: int):
        """Remove UE context"""
        g_sync.mlock(self.uectx_mux)
        if imsi in self.ue_ctx:
            del self.ue_ctx[imsi]
        g_sync.munlock(self.uectx_mux)

# Global SGW instance
g_sgw = Sgw()

def check_usage(argc: int):
    """Check command line usage"""
    if argc < 4:
        print("Usage: ./<sgw_server_exec> S11_SERVER_THREADS_COUNT S1_SERVER_THREADS_COUNT S5_SERVER_THREADS_COUNT")
        g_utils.handle_type1_error(-1, "Invalid usage error: sgwserver_checkusage")

def init(argv):
    """Initialize SGW server"""
    global g_s11_server_threads_count, g_s1_server_threads_count, g_s5_server_threads_count
    global g_s11_server_threads, g_s1_server_threads, g_s5_server_threads
    
    g_s11_server_threads_count = int(argv[1])
    g_s1_server_threads_count = int(argv[2])
    g_s5_server_threads_count = int(argv[3])
    
    g_s11_server_threads = [threading.Thread() for _ in range(g_s11_server_threads_count)]
    g_s1_server_threads = [threading.Thread() for _ in range(g_s1_server_threads_count)]
    g_s5_server_threads = [threading.Thread() for _ in range(g_s5_server_threads_count)]
    
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

def run():
    """Run SGW server"""
    global g_s11_server_threads, g_s1_server_threads, g_s5_server_threads
    
    # SGW S11 server
    print("SGW S11 server started")
    g_sgw.s11_server.run(g_sgw_s11_ip_addr, g_sgw_s11_port)
    for i in range(g_s11_server_threads_count):
        g_s11_server_threads[i] = threading.Thread(target=handle_s11_traffic)
        g_s11_server_threads[i].start()
    
    # SGW S1 server
    print("SGW S1 server started")
    g_sgw.s1_server.run(g_sgw_s1_ip_addr, g_sgw_s1_port)
    for i in range(g_s1_server_threads_count):
        g_s1_server_threads[i] = threading.Thread(target=handle_s1_traffic)
        g_s1_server_threads[i].start()
    
    # SGW S5 server
    print("SGW S5 server started")
    g_sgw.s5_server.run(g_sgw_s5_ip_addr, g_sgw_s5_port)
    for i in range(g_s5_server_threads_count):
        g_s5_server_threads[i] = threading.Thread(target=handle_s5_traffic)
        g_s5_server_threads[i].start()
    
    # Join all threads
    for thread in g_s11_server_threads:
        thread.join()
    
    for thread in g_s1_server_threads:
        thread.join()
    
    for thread in g_s5_server_threads:
        thread.join()

def handle_s11_traffic():
    """Handle S11 traffic"""
    pgw_s5_client = UdpClient()
    src_sock_addr = {}
    pkt = Packet()
    
    pgw_s5_client.set_client(g_sgw_s5_ip_addr)
    while True:
        g_sgw.s11_server.rcv(src_sock_addr, pkt)
        pkt.extract_gtp_hdr()
        
        switch (pkt.gtp_hdr.msg_type):
            case 1:  # Create session
                print("sgwserver_handles11traffic: case 1: create session")
                g_sgw.handle_create_session(src_sock_addr, pkt, pgw_s5_client)
                break
            
            case 2:  # Modify bearer
                print("sgwserver_handles11traffic: case 2: modify bearer")
                g_sgw.handle_modify_bearer(src_sock_addr, pkt)
                break
            
            case 3:  # Detach
                print("sgwserver_handles11traffic: case 3: detach")
                g_sgw.handle_detach(src_sock_addr, pkt, pgw_s5_client)
                break
            
            case 4:  # Indirect tunnel
                print("handle indirec tunnel setup: case 4: handle_indirect_tunnel_setup")
                g_sgw.handle_indirect_tunnel_setup(src_sock_addr, pkt)
                break
            
            case 5:  # Switch downlink tunnel
                print("switch downlink tunnel id to target ran: case 5: handle completion mark")
                g_sgw.handle_handover_completion(src_sock_addr, pkt)
                break
            
            case 6:  # Remove indirect tunnel
                print("remove the uplink indirect tunnel id: case 6: handle tear down")
                g_sgw.handle_indirect_tunnel_teardown_(src_sock_addr, pkt)
                break
            
            default:  # For error handling
                print("sgwserver_handles11traffic: default case:")

def handle_s1_traffic():
    """Handle S1 traffic"""
    pgw_s5_client = UdpClient()
    src_sock_addr = {}
    pkt = Packet()
    
    pgw_s5_client.set_client(g_sgw_s5_ip_addr)
    while True:
        g_sgw.s1_server.rcv(src_sock_addr, pkt)
        pkt.extract_gtp_hdr()
        
        switch (pkt.gtp_hdr.msg_type):
            case 1:  # Uplink userplane data
                print("sgwserver_handles1traffic: case 1: uplink udata")
                g_sgw.handle_uplink_udata(pkt, pgw_s5_client)
                break
            
            default:  # For error handling
                print("sgwserver_handles1traffic: default case:")

def handle_s5_traffic():
    """Handle S5 traffic"""
    enodeb_client = UdpClient()
    src_sock_addr = {}
    pkt = Packet()
    
    enodeb_client.set_client(g_sgw_s1_ip_addr)
    while True:
        g_sgw.s5_server.rcv(src_sock_addr, pkt)
        pkt.extract_gtp_hdr()
        
        switch (pkt.gtp_hdr.msg_type):
            case 3:  # Downlink userplane data
                print("sgwserver_handles5traffic: case 3: downlink udata")
                g_sgw.handle_downlink_udata(pkt, enodeb_client)
                break
            
            default:  # For error handling
                print("sgwserver_handles5traffic: default case:")

def main(argc: int, argv):
    """Main function for SGW server"""
    check_usage(argc)
    init(argv)
    run()
    return 0

if __name__ == "__main__":
    import sys
    main(len(sys.argv), sys.argv)