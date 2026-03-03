"""
Radio Access Network (RAN) implementation

"""

import time
import threading
import subprocess
import signal
from typing import Dict, List, Tuple
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
from tun import Tun
from udp_client import UdpClient
from udp_server import UdpServer
from utils import g_utils, CLOCK, MICROSECONDS

# Global configuration
g_ran_ip_addr = "10.129.26.169"
g_trafmon_ip_addr = "10.129.26.169"
g_mme_ip_addr = "10.129.26.169"
g_trafmon_port = 4000
g_mme_port = 5000
DATA_SIZE = 800
NUM_MONITORS = 50

# Handover configuration
g_ran_sctp_ip_addr = "10.129.26.169"
g_ran_port = 4905

# Simulator global variables
g_start_time = 0
g_threads_count = 0
g_req_dur = 0
g_run_dur = 0
g_tot_regs = 0
g_tot_regstime = 0
g_mux = threading.Lock()
g_umon_thread: List[threading.Thread] = []
g_dmon_thread: List[threading.Thread] = []
g_threads: List[threading.Thread] = []
g_rtt_thread = threading.Thread()
g_traf_mon = None

class RanContext:
    """RAN context information"""
    
    def __init__(self):
        self.emm_state = 0  # 0 - Deregistered, 1 - Registered
        self.ecm_state = 0  # 0 - Disconnected, 1 - Connected, 2 - Idle
        self.imsi = 0
        self.guti = 0
        self.ip_addr = ""
        self.enodeb_s1ap_ue_id = 0
        self.mme_s1ap_ue_id = 0
        self.tai = 1
        self.tau_timer = 0
        self.key = 0
        self.k_asme = 0
        self.ksi_asme = 7
        self.k_nas_enc = 0
        self.k_nas_int = 0
        self.nas_enc_algo = 0
        self.nas_int_algo = 0
        self.count = 1
        self.bearer = 0
        self.dir = 0
        self.apn_in_use = 0
        self.eps_bearer_id = 0
        self.e_rab_id = 0
        self.s1_uteid_ul = 0
        self.s1_uteid_dl = 0
        self.mcc = 1
        self.mnc = 1
        self.plmn_id = g_telecom.get_plmn_id(self.mcc, self.mnc)
        self.msisdn = 0
        self.nw_capability = 1
        
        # Handover parameters
        self.eNodeB_id = 0
        self.handover_target_eNodeB_id = 0
        self.inHandover = False
        self.indirect_s1_uteid_ul = 0
    
    def init(self, arg: int):
        self.enodeb_s1ap_ue_id = arg
        self.key = arg
        self.msisdn = 9000000000 + arg
        self.imsi = g_telecom.get_imsi(self.plmn_id, self.msisdn)

class EpcAddrs:
    """EPC address information"""
    
    def __init__(self):
        self.mme_port = g_mme_port
        self.sgw_s1_port = 0
        self.mme_ip_addr = g_mme_ip_addr
        self.sgw_s1_ip_addr = ""

class UplinkInfo:
    """Uplink information"""
    
    def __init__(self):
        self.s1_uteid_ul = 0
        self.sgw_s1_ip_addr = ""
        self.sgw_s1_port = 0
    
    def init(self, arg_s1_uteid_ul: int, arg_sgw_s1_ip_addr: str, arg_sgw_s1_port: int):
        self.s1_uteid_ul = arg_s1_uteid_ul
        self.sgw_s1_ip_addr = arg_sgw_s1_ip_addr
        self.sgw_s1_port = arg_sgw_s1_port

class TrafficMonitor:
    """Traffic monitoring functionality"""
    
    def __init__(self):
        self.uplink_info = {}  # ip_addr -> UplinkInfo
        self.uplinkinfo_mux = threading.Lock()
        self.tun = Tun()
        self.server = UdpServer()
    
    def handle_uplink_udata(self, sgw_s1_client: UdpClient):
        """Handle uplink user data"""
        pkt = Packet()
        self.tun.rcv(pkt)
        ip_addr = g_nw.get_src_ip_addr(pkt)
        
        res, s1_uteid_ul, sgw_s1_ip_addr, sgw_s1_port = self.get_uplink_info(ip_addr)
        if res:
            sgw_s1_client.set_server(sgw_s1_ip_addr, sgw_s1_port)
            pkt.prepend_gtp_hdr(1, 1, pkt.len, s1_uteid_ul)
            sgw_s1_client.snd(pkt)
    
    def handle_downlink_udata(self):
        """Handle downlink user data"""
        pkt = Packet()
        src_sock_addr = {}
        self.server.rcv(src_sock_addr, pkt)
        pkt.extract_gtp_hdr()
        pkt.truncate()
        self.tun.snd(pkt)
    
    def update_uplink_info(self, ip_addr: str, s1_uteid_ul: int, sgw_s1_ip_addr: str, sgw_s1_port: int):
        """Update uplink information"""
        g_sync.mlock(self.uplinkinfo_mux)
        self.uplink_info[ip_addr] = UplinkInfo()
        self.uplink_info[ip_addr].init(s1_uteid_ul, sgw_s1_ip_addr, sgw_s1_port)
        g_sync.munlock(self.uplinkinfo_mux)
    
    def get_uplink_info(self, ip_addr: str) -> Tuple[bool, int, str, int]:
        """Get uplink information"""
        res = False
        s1_uteid_ul = 0
        sgw_s1_ip_addr = ""
        sgw_s1_port = 0
        
        g_sync.mlock(self.uplinkinfo_mux)
        if ip_addr in self.uplink_info:
            res = True
            s1_uteid_ul = self.uplink_info[ip_addr].s1_uteid_ul
            sgw_s1_ip_addr = self.uplink_info[ip_addr].sgw_s1_ip_addr
            sgw_s1_port = self.uplink_info[ip_addr].sgw_s1_port
        g_sync.munlock(self.uplinkinfo_mux)
        
        return res, s1_uteid_ul, sgw_s1_ip_addr, sgw_s1_port

class Ran:
    """Radio Access Network (RAN) implementation"""
    
    def __init__(self):
        self.epc_addrs = EpcAddrs()
        self.mme_client = SctpClient()
        self.pkt = Packet()
        self.ran_ctx = RanContext()
        
        # Handover parameters
        self.inHandover = False
        self.indirect_s1_uteid_ul = 0
        self.eNodeB_id = 0
        self.handover_target_eNodeB_id = 0
        self.handover_state = 0  # 0 - Not in handover, 1 - Initiated, 2 - Requested, 3 - Done at target, 4 - Done at source
    
    def init(self, arg: int):
        """Initialize RAN"""
        self.ran_ctx.init(arg)
    
    def conn_mme(self):
        """Connect to MME"""
        self.mme_client.conn(self.epc_addrs.mme_ip_addr, self.epc_addrs.mme_port)
    
    def initial_attach(self):
        """Send initial attach request"""
        self.pkt.clear_pkt()
        self.pkt.append_item(self.ran_ctx.imsi)
        self.pkt.append_item(self.ran_ctx.tai)
        self.pkt.append_item(self.ran_ctx.ksi_asme)
        self.pkt.append_item(self.ran_ctx.nw_capability)
        self.pkt.prepend_s1ap_hdr(1, self.pkt.len, self.ran_ctx.enodeb_s1ap_ue_id, 0)
        self.mme_client.snd(self.pkt)
        print(f"ran_initialattach: request sent for ran: {self.ran_ctx.imsi}")
    
    def authenticate(self) -> bool:
        """Handle authentication"""
        self.mme_client.rcv(self.pkt)
        if self.pkt.len <= 0:
            return False
        
        print(f"ran_authenticate: received request for ran: {self.ran_ctx.imsi}")
        self.pkt.extract_s1ap_hdr()
        self.ran_ctx.mme_s1ap_ue_id = self.pkt.s1ap_hdr.mme_s1ap_ue_id
        
        xautn_num = self.pkt.extract_item(int)
        rand_num = self.pkt.extract_item(int)
        self.ran_ctx.ksi_asme = self.pkt.extract_item(int)
        
        print(f"ran_authenticate: autn: {xautn_num} rand: {rand_num} ksiasme: {self.ran_ctx.ksi_asme}: {self.ran_ctx.imsi}")
        
        sqn = rand_num + 1
        res = self.ran_ctx.key + sqn + rand_num
        autn_num = res + 1
        
        if autn_num != x
        if autn_num != xautn_num:
                    print(f"ran_authenticate: authentication of MME failure: {self.ran_ctx.imsi}")
                    return False
        
        print(f"ran_authenticate: autn success: {self.ran_ctx.imsi}")
        
        ck = res + 2
        ik = res + 3
        self.ran_ctx.k_asme = ck + ik + sqn + self.ran_ctx.plmn_id
        
        self.pkt.clear_pkt()
        self.pkt.append_item(res)
        self.pkt.prepend_s1ap_hdr(2, self.pkt.len, self.ran_ctx.enodeb_s1ap_ue_id, self.ran_ctx.mme_s1ap_ue_id)
        self.mme_client.snd(self.pkt)
        print(f"ran_authenticate: autn response sent to mme: {self.ran_ctx.imsi}")
        
        return True
    
    def set_security(self) -> bool:
        """Handle security setup"""
        self.mme_client.rcv(self.pkt)
        if self.pkt.len <= 0:
            return False
        
        hmac_res = bytearray(20)
        hmac_xres = bytearray(20)
        
        print(f"ran_setsecurity: received request for ran: {self.pkt.len}: {self.ran_ctx.imsi}")
        self.pkt.extract_s1ap_hdr()
        
        if HMAC_ON:
            g_integrity.rem_hmac(self.pkt, hmac_xres)
        
        self.ran_ctx.ksi_asme = self.pkt.extract_item(int)
        self.ran_ctx.nw_capability = self.pkt.extract_item(int)
        self.ran_ctx.nas_enc_algo = self.pkt.extract_item(int)
        self.ran_ctx.nas_int_algo = self.pkt.extract_item(int)
        
        self.set_crypt_context()
        self.set_integrity_context()
        
        if HMAC_ON:
            g_integrity.get_hmac(self.pkt.data[:self.pkt.len], self.ran_ctx.k_nas_int, hmac_res)
            res = g_integrity.cmp_hmacs(hmac_res, hmac_xres)
            if not res:
                print(f"ran_setsecurity: hmac security mode command failure: {self.ran_ctx.imsi}")
                g_utils.handle_type1_error(-1, "hmac error: ran_setsecurity")
        
        print(f"ran_setsecurity: security mode command success: {self.ran_ctx.imsi}")
        
        res = True
        self.pkt.clear_pkt()
        self.pkt.append_item(res)
        
        if ENC_ON:
            g_crypt.enc(self.pkt, self.ran_ctx.k_nas_enc)
        
        if HMAC_ON:
            g_integrity.add_hmac(self.pkt, self.ran_ctx.k_nas_int)
        
        self.pkt.prepend_s1ap_hdr(3, self.pkt.len, self.ran_ctx.enodeb_s1ap_ue_id, self.ran_ctx.mme_s1ap_ue_id)
        self.mme_client.snd(self.pkt)
        print(f"ran_setsecurity: security mode complete sent to mme: {self.pkt.len}: {self.ran_ctx.imsi}")
        
        return True
    
    def set_crypt_context(self):
        """Set encryption context"""
        self.ran_ctx.k_nas_enc = (self.ran_ctx.k_asme + 
                                 self.ran_ctx.nas_enc_algo + 
                                 self.ran_ctx.count + 
                                 self.ran_ctx.bearer + 
                                 self.ran_ctx.dir + 1)
    
    def set_integrity_context(self):
        """Set integrity context"""
        self.ran_ctx.k_nas_int = (self.ran_ctx.k_asme + 
                                 self.ran_ctx.nas_int_algo + 
                                 self.ran_ctx.count + 
                                 self.ran_ctx.bearer + 
                                 self.ran_ctx.dir + 1)
    
    def set_eps_session(self, traf_mon: TrafficMonitor) -> bool:
        """Handle EPS session setup"""
        self.mme_client.rcv(self.pkt)
        if self.pkt.len <= 0:
            return False
        
        print(f"ran_setepssession: attach accept received from mme: {self.pkt.len}: {self.ran_ctx.imsi}")
        self.pkt.extract_s1ap_hdr()
        
        if HMAC_ON:
            res = g_integrity.hmac_check(self.pkt, self.ran_ctx.k_nas_int)
            if not res:
                print(f"ran_setepssession: hmac attach accept failure: {self.ran_ctx.imsi}")
                g_utils.handle_type1_error(-1, "hmac error: ran_setepssession")
        
        if ENC_ON:
            g_crypt.dec(self.pkt, self.ran_ctx.k_nas_enc)
        
        self.ran_ctx.guti = self.pkt.extract_item(int)
        self.ran_ctx.eps_bearer_id = self.pkt.extract_item(int)
        self.ran_ctx.e_rab_id = self.pkt.extract_item(int)
        self.ran_ctx.s1_uteid_ul = self.pkt.extract_item(int)
        k_enodeb = self.pkt.extract_item(int)
        self.ran_ctx.nw_capability = self.pkt.extract_item(int)
        
        tai_list_size = self.pkt.extract_item(int)
        tai_list = self.pkt.extract_item(list, tai_list_size)
        self.ran_ctx.tau_timer = self.pkt.extract_item(int)
        self.ran_ctx.ip_addr = self.pkt.extract_item(str)
        self.epc_addrs.sgw_s1_ip_addr = self.pkt.extract_item(str)
        self.epc_addrs.sgw_s1_port = self.pkt.extract_item(int)
        res = self.pkt.extract_item(bool)
        
        if not res:
            print(f"ran_setepssession: attach request failure: {self.ran_ctx.imsi}")
            return False
        
        traf_mon.update_uplink_info(self.ran_ctx.ip_addr, self.ran_ctx.s1_uteid_ul, 
                                   self.epc_addrs.sgw_s1_ip_addr, self.epc_addrs.sgw_s1_port)
        self.ran_ctx.s1_uteid_dl = self.ran_ctx.s1_uteid_ul
        
        self.pkt.clear_pkt()
        self.pkt.append_item(self.ran_ctx.eps_bearer_id)
        self.pkt.append_item(self.ran_ctx.s1_uteid_dl)
        
        if ENC_ON:
            g_crypt.enc(self.pkt, self.ran_ctx.k_nas_enc)
        
        if HMAC_ON:
            g_integrity.add_hmac(self.pkt, self.ran_ctx.k_nas_int)
        
        self.pkt.prepend_s1ap_hdr(4, self.pkt.len, self.ran_ctx.enodeb_s1ap_ue_id, self.ran_ctx.mme_s1ap_ue_id)
        self.mme_client.snd(self.pkt)
        print(f"ran_setepssession: attach complete sent to mme: {self.pkt.len}: {self.ran_ctx.imsi}")
        
        self.ran_ctx.emm_state = 1
        self.ran_ctx.ecm_state = 1
        
        return True
    
    def transfer_data(self, arg_rate: int):
        """Transfer data using iperf"""
        rate = f" -b {arg_rate}M"
        mtu = f" -M {DATA_SIZE}"
        dur = " -t 300"
        redir_err = " 2>&1"
        server_ip_addr = "172.16.0.2"
        server_port = self.ran_ctx.key + 55000
        
        g_nw.add_itf(self.ran_ctx.key, self.ran_ctx.ip_addr + "/8")
        cmd = f"iperf3 -B {self.ran_ctx.ip_addr} -c {server_ip_addr} -p {server_port}{rate}{mtu}{dur}{redir_err}"
        print(cmd)
        subprocess.run(cmd, shell=True)
        print(f"ran_transferdata: transfer done for ran: {self.ran_ctx.imsi}")
    
    def initiate_handover(self):
        """Initiate handover procedure"""
        self.handover_state = 1  # initiated handover
        self.ran_ctx.eNodeB_id = 1
        handover_type = 0  # handover type: 0 for intra MME
        self.ran_ctx.handover_target_eNodeB_id = 2  # handover to ran with id 2
        
        self.pkt.clear_pkt()
        self.pkt.append_item(handover_type)
        self.pkt.append_item(self.eNodeB_id)  # source enbid 1
        self.pkt.append_item(self.ran_ctx.handover_target_eNodeB_id)  # target enbid 2
        self.pkt.append_item(self.ran_ctx.enodeb_s1ap_ue_id)
        self.pkt.append_item(self.ran_ctx.mme_s1ap_ue_id)
        self.pkt.prepend_s1ap_hdr(7, self.pkt.len, self.ran_ctx.enodeb_s1ap_ue_id, self.ran_ctx.mme_s1ap_ue_id)
        
        self.mme_client.snd(self.pkt)
        print("ran_handover: Handover intiation triggered")
    
    def handle_handover(self, pkt: Packet):
        """Handle handover request (target RAN)"""
        t_enb = pkt.extract_item(int)
        self.handover_state = 2  # HO requested at target RAN
        
        # receive s1ap headers for the UE
        self.ran_ctx.enodeb_s1ap_ue_id = pkt.extract_item(int)
        self.ran_ctx.mme_s1ap_ue_id = pkt.extract_item(int)
        
        # need this when we upload data to sgw, after handover completes
        self.ran_ctx.s1_uteid_ul = pkt.extract_item(int)
        
        self.pkt.clear_pkt()
        self.pkt.append_item(self.ran_ctx.enodeb_s1ap_ue_id)
        self.pkt.prepend_s1ap_hdr(8, self.pkt.len, self.ran_ctx.enodeb_s1ap_ue_id, self.ran_ctx.mme_s1ap_ue_id)
        
        self.mme_client.conn(self.epc_addrs.mme_ip_addr, self.epc_addrs.mme_port)
        self.mme_client.snd(self.pkt)
        
        self.handover_state = 3
        print("target Ran acknowledges handover: Handover intiation triggered 452")
    
    def indirect_tunnel_complete(self, pkt: Packet):
        """Handle indirect tunnel setup completion (source RAN)"""
        self.handover_state = 4  # HO done now we can redirect packet through indirect tunnel id
        self.ran_ctx.indirect_s1_uteid_ul = pkt.extract_item(int)
        print("indirect tunnel setup complete")
    
    def complete_handover(self):
        """Complete handover procedure (target RAN)"""
        self.pkt.clear_pkt()
        self.pkt.prepend_s1ap_hdr(9, self.pkt.len, self.ran_ctx.enodeb_s1ap_ue_id, self.ran_ctx.mme_s1ap_ue_id)
        
        self.mme_client.snd(self.pkt)
        print("ran_handover: teardown initiated from target ran")
    
    def request_tear_down(self, pkt: Packet):
        """Request indirect tunnel teardown (source RAN)"""
        self.ran_ctx.s1_uteid_ul = 0  # clearing uplink id
        self.pkt.clear_pkt()
        self.pkt.append_item(self.ran_ctx.indirect_s1_uteid_ul)  # send the indirect teid that needs to be removed from sgw
        
        self.pkt.prepend_s1ap_hdr(10, self.pkt.len, self.ran_ctx.enodeb_s1ap_ue_id, self.ran_ctx.mme_s1ap_ue_id)
        
        self.mme_client.snd(self.pkt)
        print("ran_handover: teardown completed at S Ran")
    
    def detach(self) -> bool:
        """Handle detach procedure"""
        detach_type = 1
        
        self.pkt.clear_pkt()
        self.pkt.append_item(self.ran_ctx.guti)
        self.pkt.append_item(self.ran_ctx.ksi_asme)
        self.pkt.append_item(detach_type)
        
        if ENC_ON:
            g_crypt.enc(self.pkt, self.ran_ctx.k_nas_enc)
        
        if HMAC_ON:
            g_integrity.add_hmac(self.pkt, self.ran_ctx.k_nas_int)
        
        self.pkt.prepend_s1ap_hdr(5, self.pkt.len, self.ran_ctx.enodeb_s1ap_ue_id, self.ran_ctx.mme_s1ap_ue_id)
        self.mme_client.snd(self.pkt)
        print(f"ran_detach: detach request sent to mme: {self.pkt.len}: {self.ran_ctx.imsi}")
        
        self.mme_client.rcv(self.pkt)
        if self.pkt.len <= 0:
            return False
        
        print(f"ran_detach: detach complete received from mme: {self.pkt.len}: {self.ran_ctx.imsi}")
        self.pkt.extract_s1ap_hdr()
        
        if HMAC_ON:
            res = g_integrity.hmac_check(self.pkt, self.ran_ctx.k_nas_int)
            if not res:
                print(f"ran_detach: hmac detach failure: {self.ran_ctx.imsi}")
                g_utils.handle_type1_error(-1, "hmac error: ran_detach")
        
        if ENC_ON:
            g_crypt.dec(self.pkt, self.ran_ctx.k_nas_enc)
        
        res = self.pkt.extract_item(bool)
        if not res:
            print(f"ran_detach: detach failure: {self.ran_ctx.imsi}")
            return False
        
        print(f"ran_detach: detach successful: {self.ran_ctx.imsi}")
        return True