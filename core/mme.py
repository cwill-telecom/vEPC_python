"""
Mobility Management Entity (MME) implementation

"""

import threading
import signal
from typing import Dict, List
from diameter import Diameter
from gtp import Gtp
from network import Network
from packet import Packet
from s1ap import S1ap
from sctp_client import SctpClient
from sctp_server import SctpServer
from security import g_crypt, g_integrity, HMAC_ON, ENC_ON
from sync import g_sync
from telecom import g_telecom
from udp_client import UdpClient
from utils import g_utils

# Global configuration
g_trafmon_ip_addr = "10.129.26.169"
g_mme_ip_addr = "10.129.26.169"
g_hss_ip_addr = "10.129.26.169"
g_sgw_s11_ip_addr = "10.129.26.169"
g_sgw_s1_ip_addr = "10.129.26.169"
g_sgw_s5_ip_addr = "10.129.26.169"
g_pgw_s5_ip_addr = "10.129.26.169"

g_trafmon_port = 4000
g_mme_port = 5000
g_hss_port = 6000
g_sgw_s11_port = 7000
g_sgw_s1_port = 7100
g_sgw_s5_port = 7200
g_pgw_s5_port = 8000

g_timer = 100

# Handover configuration
t_ran_ip_addr = "10.129.26.169"
t_ran_port = 4905
s_ran_ip_addr = "10.129.26.169"
s_ran_port = 4905

g_workers_count = 0
hss_clients: List[SctpClient] = []
sgw_s11_clients: List[UdpClient] = []

class UeContext:
    """UE context information"""
    
    def __init__(self):
        self.emm_state = 0  # 0 - Deregistered, 1 - Registered
        self.ecm_state = 0  # 0 - Disconnected, 1 - Connected, 2 - Idle
        self.imsi = 0
        self.ip_addr = ""
        self.enodeb_s1ap_ue_id = 0
        self.mme_s1ap_ue_id = 0
        self.tai = 0
        self.tau_timer = 0
        self.ksi_asme = 0
        self.k_asme = 0
        self.k_nas_enc = 0
        self.k_nas_int = 0
        self.nas_enc_algo = 0
        self.nas_int_algo = 0
        self.count = 1
        self.bearer = 0
        self.dir = 1
        self.default_apn = 0
        self.apn_in_use = 0
        self.eps_bearer_id = 0
        self.e_rab_id = 0
        self.s1_uteid_ul = 0
        self.s1_uteid_dl = 0
        self.s5_uteid_ul = 0
        self.s5_uteid_dl = 0
        self.xres = 0
        self.nw_type = 0
        self.nw_capability = 0
        self.pgw_s5_ip_addr = ""
        self.pgw_s5_port = 0
        self.s11_cteid_mme = 0
        self.s11_cteid_sgw = 0
        self.tai_list = []
    
    def init(self, arg_imsi: int, arg_enodeb_s1ap_ue_id: int, arg_mme_s1ap_ue_id: int, arg_tai: int, arg_nw_capability: int):
        self.imsi = arg_imsi
        self.enodeb_s1ap_ue_id = arg_enodeb_s1ap_ue_id
        self.mme_s1ap_ue_id = arg_mme_s1ap_ue_id
        self.tai = arg_tai
        self.nw_capability = arg_nw_capability

class MmeIds:
    """MME identification information"""
    
    def __init__(self):
        self.mcc = 1
        self.mnc = 1
        self.plmn_id = g_telecom.get_plmn_id(self.mcc, self.mnc)
        self.mmegi = 1
        self.mmec = 1
        self.mmei = g_telecom.get_mmei(self.mmegi, self.mmec)
        self.gummei = g_telecom.get_gummei(self.plmn_id, self.mmei)

class Mme:
    """Mobility Management Entity (MME) implementation"""
    
    def __init__(self):
        self.mme_ids = MmeIds()
        self.ue_count = 0
        self.s1mme_id = {}  # mme_s1ap_ue_id -> guti
        self.ue_ctx = {}    # guti -> UeContext
        self.s1mmeid_mux = threading.Lock()
        self.uectx_mux = threading.Lock()
        self.server = SctpServer()
    
    def clrstl(self):
        """Clear all data structures"""
        self.s1mme_id.clear()
        self.ue_ctx.clear()
    
    def get_s11cteidmme(self, guti: int) -> int:
        """Get S11 control plane TEID from MME"""
        tem = str(guti)
        tem = tem[-9:]  # Extract last 9 digits of UE MSISDN
        s11_cteid_mme = int(tem)
        return s11_cteid_mme
    
    def handle_initial_attach(self, conn_fd, pkt: Packet, hss_client: SctpClient):
        """Handle initial attach request"""
        imsi = pkt.extract_item(int)
        tai = pkt.extract_item(int)
        ksi_asme = pkt.extract_item(int)  # No use in this case
        nw_capability = pkt.extract_item(int)  # No use in this case
        
        enodeb_s1ap_ue_id = pkt.s1ap_hdr.enodeb_s1ap_ue_id
        guti = g_telecom.get_guti(self.mme_ids.gummei, imsi)
        
        print(f"mme_handleinitialattach: initial attach req received: {guti}")
        
        g_sync.mlock(self.s1mmeid_mux)
        self.ue_count += 1
        mme_s1ap_ue_id = self.ue_count
        self.s1mme_id[mme_s1ap_ue_id] = guti
        g_sync.munlock(self.s1mmeid_mux)
        
        g_sync.mlock(self.uectx_mux)
        self.ue_ctx[guti] = UeContext()
        self.ue_ctx[guti].init(imsi, enodeb_s1ap_ue_id, mme_s1ap_ue_id, tai, nw_capability)
        nw_type = self.ue_ctx[guti].nw_type
        print(f"mme_handleinitialattach: ue entry added: {guti}")
        g_sync.munlock(self.uectx_mux)
        
        pkt.clear_pkt()
        pkt.append_item(imsi)
        pkt.append_item(self.mme_ids.plmn_id)
        num_autn_vectors = 1
        pkt.append_item(num_autn_vectors)
        pkt.append_item(nw_type)
        pkt.prepend_diameter_hdr(1, pkt.len)
        hss_client.snd(pkt)
        print(f"mme_handleinitialattach: request sent to hss: {guti}")
        
        hss_client.rcv(pkt)
        
        pkt.extract_diameter_hdr()
        autn_num = pkt.extract_item(int)
        rand_num = pkt.extract_item(int)
        xres = pkt.extract_item(int)
        k_asme = pkt.extract_item(int)
        
        g_sync.mlock(self.uectx_mux)
        self.ue_ctx[guti].xres = xres
        self.ue_ctx[guti].k_asme = k_asme
        self.ue_ctx[guti].ksi_asme = 1
        ksi_asme = self.ue_ctx[guti].ksi_asme
        g_sync.munlock(self.uectx_mux)
        
        print(f"mme_handleinitialattach: autn:{autn_num} rand:{rand_num} xres:{xres} k_asme:{k_asme} {guti}")
        
        pkt.clear_pkt()
        pkt.append_item(autn_num)
        pkt.append_item(rand_num)
        pkt.append_item(ksi_asme)
        pkt.prepend_s1ap_hdr(1, pkt.len, enodeb_s1ap_ue_id, mme_s1ap_ue_id)
        self.server.snd(conn_fd, pkt)
        print(f"mme_handleinitialattach: autn request sent to ran: {guti}")
    
    def handle_autn(self, conn_fd, pkt: Packet) -> bool:
        """Handle authentication response"""
        guti = self.get_guti(pkt)
        if guti == 0:
            print(f"mme_handleautn: zero guti {pkt.s1ap_hdr.mme_s1ap_ue_id} {pkt.len}: {guti}")
            g_utils.handle_type1_error(-1, "Zero guti: mme_handleautn")
        
        res = pkt.extract_item(int)
        g_sync.mlock(self.uectx_mux)
        xres = self.ue_ctx[guti].xres
        g_sync.munlock(self.uectx_mux)
        
        if res == xres:
            print(f"mme_handleautn: Authentication successful: {guti}")
            return True
        else:
            self.rem_itfid(pkt.s1ap_hdr.mme_s1ap_ue_id)
            self.rem_uectx(guti)
            return False
    
    def handle_security_mode_cmd(self, conn_fd, pkt: Packet):
        """Handle security mode command"""
        guti = self.get_guti(pkt)
        if guti == 0:
            print(f"mme_handlesecuritymodecmd: zero guti {pkt.s1ap_hdr.mme_s1ap_ue_id} {pkt.len}: {guti}")
            g_utils.handle_type1_error(-1, "Zero guti: mme_handlesecuritymodecmd")
        
        self.set_crypt_context(guti)
        self.set_integrity_context(guti)
        
        g_sync.mlock(self.uectx_mux)
        ksi_asme = self.ue_ctx[guti].ksi_asme
        nw_capability = self.ue_ctx[guti].nw_capability
        nas_enc_algo = self.ue_ctx[guti].nas_enc_algo
        nas_int_algo = self.ue_ctx[guti].nas_int_algo
        k_nas_enc = self.ue_ctx[guti].k_nas_enc
        k_nas_int = self.ue_ctx[guti].k_nas_int
        g_sync.munlock(self.uectx_mux)
        
        pkt.clear_pkt()
        pkt.append_item(ksi_asme)
        pkt.append_item(nw_capability)
        pkt.append_item(nas_enc_algo)
        pkt.append_item(nas_int_algo)
        
        if HMAC_ON:
            g_integrity.add_hmac(pkt, k_nas_int)
        
        pkt.prepend_s1ap_hdr(2, pkt.len, pkt.s1ap_hdr.enodeb_s1ap_ue_id, pkt.s1ap_hdr.mme_s1ap_ue_id)
        self.server.snd(conn_fd, pkt)
        print(f"mme_handlesecuritymodecmd: security mode command sent: {pkt.len}: {guti}")
    
    def set_crypt_context(self, guti: int):
        """Set encryption context for UE"""
        g_sync.mlock(self.uectx_mux)
        self.ue_ctx[guti].nas_enc_algo = 1
        self.ue_ctx[guti].k_nas_enc = (self.ue_ctx[guti].k_asme + 
                                        self.ue_ctx[guti].nas_enc_algo + 
                                        self.ue_ctx[guti].count + 
                                        self.ue_ctx[guti].bearer + 
                                        self.ue_ctx[guti].dir)
        g_sync.munlock(self.uectx_mux)
    
    def set_integrity_context(self, guti: int):
        """Set integrity context for UE"""
        g_sync.mlock(self.uectx_mux)
        self.ue_ctx[guti].nas_int_algo = 1
        self.ue_ctx[guti].k_nas_int = (self.ue_ctx[guti].k_asme + 
                                        self.ue_ctx[guti].nas_int_algo + 
                                        self.ue_ctx[guti].count + 
                                        self.ue_ctx[guti].bearer + 
                                        self.ue_ctx[guti].dir)
        g_sync.munlock(self.uectx_mux)
    
    def handle_security_mode_complete(self, conn_fd, pkt: Packet) -> bool:
        """Handle security mode complete"""
        guti = self.get_guti(pkt)
        if guti == 0:
            print(f"mme_handlesecuritymodecomplete: zero guti {pkt.s1ap_hdr.mme_s1ap_ue_id} {pkt.len}: {guti}")
            g_utils.handle_type1_error(-1, "Zero guti: mme_handlesecuritymodecomplete")
        
        g_sync.mlock(self.uectx_mux)
        k_nas_enc = self.ue_ctx[guti].k_nas_enc
        k_nas_int = self.ue_ctx[guti].k_nas_int
        g_sync.munlock(self.uectx_mux)
        
        print(f"mme_handlesecuritymodecomplete: security mode complete received: {pkt.len}: {guti}")
        
        if HMAC_ON:
            res = g_integrity.hmac_check(pkt, k_nas_int)
            if not res:
                print(f"mme_handlesecuritymodecomplete: hmac failure: {guti}")
                g_utils.handle_type1_error(-1, "hmac failure: mme_handlesecuritymodecomplete")
        
        if ENC_ON:
            g_crypt.dec(pkt, k_nas_enc)
        
        res = pkt.extract_item(int)
        if not res:
            print(f"mme_handlesecuritymodecomplete: security mode complete failure: {guti}")
            return False
        else:
            print(f"mme_handlesecuritymodecomplete: security mode complete success: {guti}")
            return True
    
    def handle_location_update(self, pkt: Packet, hss_client: SctpClient):
        """Handle location update"""
        guti = self.get_guti(pkt)
        if guti == 0:
            print(f"mme_handlelocationupdate: zero guti {pkt.s1ap_hdr.mme_s1ap_ue_id} {pkt.len}: {guti}")
            g_utils.handle_type1_error(-1, "Zero guti: mme_handlelocationupdate")
        
        g_sync.mlock(self.uectx_mux)
        imsi = self.ue_ctx[guti].imsi
        g_sync.munlock(self.uectx_mux)
        
        pkt.clear_pkt()
        pkt.append_item(imsi)
        pkt.append_item(self.mme_ids.mmei)
        pkt.prepend_diameter_hdr(2, pkt.len)
        hss_client.snd(pkt)
        print(f"mme_handlelocationupdate: loc update sent to hss: {guti}")
        
        hss_client.rcv(pkt)
        print(f"mme_handlelocationupdate: loc update response received from hss: {guti}")
        
        pkt.extract_diameter_hdr()
        default_apn = pkt.extract_item(int)
        g_sync.mlock(self.uectx_mux)
        self.ue_ctx[guti].default_apn = default_apn
        self.ue_ctx[guti].apn_in_use = self.ue_ctx[guti].default_apn
        g_sync.munlock(self.uectx_mux)
    
    def handle_create_session(self, conn_fd, pkt: Packet, sgw_client: UdpClient):
        """Handle create session request"""
        guti = self.get_guti(pkt)
        if guti == 0:
            print(f"mme_handlecreatesession: zero guti {pkt.s1ap_hdr.mme_s1ap_ue_id} {pkt.len}: {guti}")
            g_utils.handle_type1_error(-1, "Zero guti: mme_handlecreatesession")
        
        eps_bearer_id = 5
        self.set_pgw_info(guti)
        
        g_sync.mlock(self.uectx_mux)
        self.ue_ctx[guti].s11_cteid_mme = self.get_s11cteidmme(guti)
        self.ue_ctx[guti].eps_bearer_id = eps_bearer_id
        s11_cteid_mme = self.ue_ctx[guti].s11_cteid_mme
        imsi = self.ue_ctx[guti].imsi
        eps_bearer_id = self.ue_ctx[guti].eps_bearer_id
        pgw_s5_ip_addr = self.ue_ctx[guti].pgw_s5_ip_addr
        pgw_s5_port = self.ue_ctx[guti].pgw_s5_port
        apn_in_use = self.ue_ctx[guti].apn_in_use
        tai = self.ue_ctx[guti].tai
        g_sync.munlock(self.uectx_mux)
        
        pkt.clear_pkt()
        pkt.append_item(s11_cteid_mme)
        pkt.append_item(imsi)
        pkt.append_item(eps_bearer_id)
        pkt.append_item(pgw_s5_ip_addr)
        pkt.append_item(pgw_s5_port)
        pkt.append_item(apn_in_use)
        pkt.append_item(tai)
        pkt.prepend_gtp_hdr(2, 1, pkt.len, 0)
        sgw_client.snd(pkt)
        print(f"mme_createsession: create session request sent to sgw: {guti}")
        
        sgw_client.rcv(pkt)
        print(f"mme_createsession: create session response received sgw: {guti}")
        
        pkt.extract_gtp_hdr()
        s11_cteid_sgw = pkt.extract_item(int)
        ue_ip_addr = pkt.extract_item(str)
        s1_uteid_ul = pkt.extract_item(int)
        s5_uteid_ul = pkt.extract_item(int)
        s5_uteid_dl = pkt.extract_item(int)
        
        g_sync.mlock(self.uectx_mux)
        self.ue_ctx[guti].ip_addr = ue_ip_addr
        self.ue_ctx[guti].s11_cteid_sgw = s11_cteid_sgw
        self.ue_ctx[guti].s1_uteid_ul = s1_uteid_ul
        self.ue_ctx[guti].s5_uteid_ul = s5_uteid_ul
        self.ue_ctx[guti].s5_uteid_dl = s5_uteid_dl
        self.ue_ctx[guti].tai_list = [self.ue_ctx[guti].tai]
        self.ue_ctx[guti].tau_timer = g_timer
        self.ue_ctx[guti].e_rab_id = self.ue_ctx[guti].eps_bearer_id
        self.ue_ctx[guti].k_enodeb = self.ue_ctx[guti].k_asme
        e_rab_id = self.ue_ctx[guti].e_rab_id
        k_enodeb = self.ue_ctx[guti].k_enodeb
        nw_capability = self.ue_ctx[guti].nw_capability
        tai_list = self.ue_ctx[guti].tai_list
        tau_timer = self.ue_ctx[guti].tau_timer
        k_nas_enc = self.ue_ctx[guti].k_nas_enc
        k_nas_int = self.ue_ctx[guti].k_nas_int
        g_sync.munlock(self.uectx_mux)
        
        res = True
        tai_list_size = 1
        
        pkt.clear_pkt()
        pkt.append_item(guti)
        pkt.append_item(eps_bearer_id)
        pkt.append_item(e_rab_id)
        pkt.append_item(s1_uteid_ul)
        pkt.append_item(k_enodeb)
        pkt.append_item(nw_capability)
        pkt.append_item(tai_list_size)
        pkt.append_item(tai_list)
        pkt.append_item(tau_timer)
        pkt.append_item(ue_ip_addr)
        pkt.append_item(g_sgw_s1_ip_addr)
        pkt.append_item(g_sgw_s1_port)
        pkt.append_item(res)
        
        if ENC_ON:
            g_crypt.enc(pkt, k_nas_enc)
        
        if HMAC_ON:
            g_integrity.add_hmac(pkt, k_nas_int)
        
        pkt.prepend_s1ap_hdr(3, pkt.len, pkt.s1ap_hdr.enodeb_s1ap_ue_id, pkt.s1ap_hdr.mme_s1ap_ue_id)
        self.server.snd(conn_fd, pkt)
        print(f"mme_createsession: attach accept sent to ue: {pkt.len}: {guti}")
    
    def set_pgw_info(self, guti: int):
        """Set PGW information for UE"""
        g_sync.mlock(self.uectx_mux)
        self.ue_ctx[guti].pgw_s5_port = g_pgw_s5_port
        self.ue_ctx[guti].pgw_s5_ip_addr = g_pgw_s5_ip_addr
        g_sync.munlock(self.uectx_mux)
    
    def get_guti(self, pkt: Packet) -> int:
        """Get GUTI from packet"""
        mme_s1ap_ue_id = pkt.s1ap_hdr.mme_s1ap_ue_id
        guti = 0
        
        g_sync.mlock(self.s1mmeid_mux)
        if mme_s1ap_ue_id in self.s1mme_id:
            guti = self.s1mme_id[mme_s1ap_ue_id]
        g_sync.munlock(self.s1mmeid_mux)
        
        return guti
    
    def rem_itfid(self, mme_s1ap_ue_id: int):
        """Remove interface ID"""
        g_sync.mlock(self.s1mmeid_mux)
        if mme_s1ap_ue_id in self.s1mme_id:
            del self.s1mme_id[mme_s1ap_ue_id]
        g_sync.munlock(self.s1mmeid_mux)
    
    def rem_uectx(self, guti: int):
        """Remove UE context"""
        g_sync.mlock(self.uectx_mux)
        if guti in self.ue_ctx:
            del self.ue_ctx[guti]
        g_sync.munlock(self.uectx_mux)
    
    # Handover methods
    def handle_handover(self, pkt: Packet):
        """Handle handover request"""
        self.request_target_RAN(pkt)
    
    def setup_indirect_tunnel(self, pkt: Packet):
        """Setup indirect tunnel for handover"""
        print("set-up indirect tunnel at mme")
        
        sgw_client = UdpClient()
        guti = self.get_guti(pkt)
        s1_uteid_dl_ho = pkt.extract_item(int)
        s1_uteid_ul = 0
        s11_cteid_sgw = 0
        res = False
        
        sgw_client.conn(g_mme_ip_addr, g_sgw_s11_ip_addr, g_sgw_s11_port)
        
        g_sync.mlock(self.uectx_mux)
        s11_cteid_sgw = self.ue_ctx[guti].s11_cteid_sgw
        g_sync.munlock(self.uectx_mux)
        
        pkt.clear_pkt()
        pkt.append_item(s1_uteid_dl_ho)
        pkt.prepend_gtp_hdr(2, 4, pkt.len, s11_cteid_sgw)
        sgw_client.snd(pkt)
        sgw_client.rcv(pkt)
        
        pkt.extract_gtp_hdr()
        res = pkt.extract_item(bool)  # indirect uplink teid for senb
        s1_uteid_ul = pkt.extract_item(int)
        
        to_source_ran_client = SctpClient()
        to_source_ran_client.conn(s_ran_ip_addr, s_ran_port)
        
        if res:
            pkt.clear_pkt()
            pkt.append_item(s1_uteid_ul)
            pkt.prepend_s1ap_hdr(8, pkt.len, pkt.s1ap_hdr.enodeb_s1ap_ue_id, pkt.s1ap_hdr.mme_s1ap_ue_id)
            to_source_ran_client.snd(pkt)
        
        print("indirect tunnel setup complete at mme")
    
    def request_target_RAN(self, pkt: Packet):
        """Request target RAN for handover"""
        handover_type = pkt.extract_item(int)
        s_enb = pkt.extract_item(int)
        t_enb = pkt.extract_item(int)
        enodeb_s1ap_ue_id = pkt.extract_item(int)
        mme_s1ap_ue_id = pkt.extract_item(int)
        guti = self.get_guti(pkt)
        
        print("req_tar_ran")
        
        pkt.clear_pkt()
        pkt.append_item(t_enb)
        pkt.append_item(enodeb_s1ap_ue_id)
        pkt.append_item(mme_s1ap_ue_id)
        
        g_sync.mlock(self.uectx_mux)
        pkt.append_item(self.ue_ctx[guti].s1_uteid_ul)
        g_sync.munlock(self.uectx_mux)
        
        pkt.prepend_s1ap_hdr(7, pkt.len, pkt.s1ap_hdr.enodeb_s1ap_ue_id, pkt.s1ap_hdr.mme_s1ap_ue_id)
        
        to_target_ran_client = SctpClient()
        to_target_ran_client.conn(t_ran_ip_addr, t_ran_port)
        to_target_ran_client.snd(pkt)
        print("send to target ran done from mme")
    
    def handle_handover_completion(self, pkt: Packet):
        """Handle handover completion"""
        print("handover completion")
        
        sgw_client = UdpClient()
        guti = self.get_guti(pkt)
        s1_uteid_dl_ho = 0
        s1_uteid_ul = 0
        s11_cteid_sgw = 0
        res = False
        
        sgw_client.conn(g_mme_ip_addr, g_sgw_s11_ip_addr, g_sgw_s11_port)
        
        g_sync.mlock(self.uectx_mux)
        s11_cteid_sgw = self.ue_ctx[guti].s11_cteid_sgw
        g_sync.munlock(self.uectx_mux)
        
        pkt.clear_pkt()
        pkt.append_item(1)  # success marker
        pkt.prepend_gtp_hdr(2, 5, pkt.len, s11_cteid_sgw)
        sgw_client.snd(pkt)
        sgw_client.rcv(pkt)
        
        pkt.extract_gtp_hdr()
        res = pkt.extract_item(bool)
        
        to_source_ran_client = SctpClient()
        to_source_ran_client.conn(s_ran_ip_addr, s_ran_port)
        
        if res:
            pkt.clear_pkt()
            pkt.append_item(res)
            pkt.prepend_s1ap_hdr(9, pkt.len, pkt.s1ap_hdr.enodeb_s1ap_ue_id, pkt.s1ap_hdr.mme_s1ap_ue_id)
            to_source_ran_client.snd(pkt)
        
        print(f"handle_handover_completion: handover setup completed")
    
    def teardown_indirect_tunnel(self, pkt: Packet):
        """Teardown indirect tunnel"""
        print("tear down at mme")
        res = False
        sgw_client = UdpClient()
        guti = self.get_guti(pkt)
        s1_uteid_dl_ho = 0
        s1_uteid_ul = 0
        s11_cteid_sgw = 0
        s1_uteid_ul_ho = 0
        
        s1_uteid_ul_ho = pkt.extract_item(int)
        
        sgw_client.conn(g_mme_ip_addr, g_sgw_s11_ip_addr, g_sgw_s11_port)
        guti = self.get_guti(pkt)
        
        g_sync.mlock(self.uectx_mux)
        s11_cteid_sgw = self.ue_ctx[guti].s11_cteid_sgw
        g_sync.munlock(self.uectx_mux)
        
        pkt.clear_pkt()
        pkt.append_item(s1_uteid_ul_ho)
        pkt.prepend_gtp_hdr(2, 6, pkt.len, s11_cteid_sgw)
        sgw_client.snd(pkt)
        sgw_client.rcv(pkt)
        
        pkt.extract_gtp_hdr()
        res = pkt.extract_item(bool)
        
        if res:
            print("tear down completed")

# Global MME instance
g_mme = Mme()

def check_usage(argc: int):
    """Check command line usage"""
    if argc < 2:
        print("Usage: ./<mme_server_exec> THREADS_COUNT")
        g_utils.handle_type1_error(-1, "Invalid usage error: mmeserver_checkusage")

def init(argv):
    """Initialize MME server"""
    global g_workers_count, hss_clients, sgw_s11_clients
    g_workers_count = int(argv[1])
    hss_clients = [SctpClient() for _ in range(g_workers_count)]
    sgw_s11_clients = [UdpClient() for _ in range(g_workers_count)]
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

def run():
    """Run MME server"""
    global hss_clients, sgw_s11_clients
    
    print("MME server started")
    
    for i in range(g_workers_count):
        hss_clients[i].conn(g_hss_ip_addr, g_hss_port)
        print("hss")
        sgw_s11_clients[i].conn(g_mme_ip_addr, g_sgw_s11_ip_addr, g_sgw_s11_port)
    
    g_mme.server.run(g_mme_ip_addr, g_mme_port, g_workers_count, handle_ue)

def handle_ue(conn_fd, worker_id: int) -> int:
    """Handle UE connection"""
    global hss_clients, sgw_s11_clients
    
    pkt = Packet()
    
    g_mme.server.rcv(conn_fd, pkt)
    if pkt.len <= 0:
        print("mmeserver_handleue: Connection closed")
        return 0
    
    pkt.extract_s1ap_hdr()
    if pkt.s1ap_hdr.mme_s1ap_ue_id == 0:
        switch (pkt.s1ap_hdr.msg_type):
            case 1:  # Initial Attach request
                print("mmeserver_handleue: case 1: initial attach")
                g_mme.handle_initial_attach(conn_fd, pkt, hss_clients[worker_id])
                break
            
            default:  # For error handling
                print("mmeserver_handleue: default case: new")
                break
    
    elif pkt.s1ap_hdr.mme_s1ap_ue_id > 0:
        switch (pkt.s1ap_hdr.msg_type):
            case 2:  # Authentication response
                print("mmeserver_handleue: case 2: authentication response")
                res = g_mme.handle_autn(conn_fd, pkt)
                if res:
                    g_mme.handle_security_mode_cmd(conn_fd, pkt)
                break
            
            case 3:  # Security Mode Complete
                print("mmeserver_handleue: case 3: security mode complete")
                res = g_mme.handle_security_mode_complete(conn_fd, pkt)
                if res:
                    g_mme.handle_create_session(conn_fd, pkt, sgw_s11_clients[worker_id])
                break
            
            case 4:  # Attach Complete
                print("mmeserver_handleue: case 4: attach complete")
                g_mme.handle_attach_complete(pkt)
                g_mme.handle_modify_bearer(pkt, sgw_s11_clients[worker_id])
                break
            
            case 5:  # Detach request
                print("mmeserver_handleue: case 5: detach request")
                g_mme.handle_detach(conn_fd, pkt, sgw_s11_clients[worker_id])
                break
            
            case 7:  # Handover request
                print("mmeserver_handleue: case 7:")
                g_mme.handle_handover(pkt)
                break
            
            case 8:  # Indirect tunnel setup
                print("mmeserver_handleue: case 8:")
                g_mme.setup_indirect_tunnel(pkt)
                break
            
            case 9:  # Handover completion
                print("mmeserver_handleue: case 9:")
                g_mme.handle_handover_completion(pkt)
                break
            
            case 10:  # Indirect tunnel teardown
                print("send indirect tunnel teardwn req: case 10:")
                g_mme.teardown_indirect_tunnel(pkt)
                break
            
            default:  # For error handling
                print("mmeserver_handleue: default case: attached")
                break
    
    return 1

def main(argc: int, argv):
    """Main function for MME server"""
    check_usage(argc)
    init(argv)
    run()
    return 0

if __name__ == "__main__":
    import sys
    main(len(sys.argv), sys.argv)