"""
Home Subscriber Server (HSS) implementation

"""

import threading
import signal
from typing import Dict, List
from diameter import Diameter
from mysql import MySql
from network import Network
from packet import Packet
from s1ap import S1ap
from sctp_server import SctpServer
from sync import g_sync
from utils import g_utils

# Global configuration
g_hss_ip_addr = "192.168.1.80"
g_hss_port = 6000
g_workers_count = 0

class Hss:
    """Home Subscriber Server (HSS) implementation"""
    
    def __init__(self):
        self.mysql_client_mux = threading.Lock()
        self.server = SctpServer()
        self.mysql_client = MySql()
    
    def handle_mysql_conn(self):
        """Handle MySQL connection"""
        g_sync.mlock(self.mysql_client_mux)
        self.mysql_client.conn()
        g_sync.munlock(self.mysql_client_mux)
    
    def get_autn_info(self, imsi: int, key: int, rand_num: int):
        """Get authentication information from database"""
        query = f"select key_id, rand_num from autn_info where imsi = {imsi}"
        print(f"hss_getautninfo: {query}")
        
        g_sync.mlock(self.mysql_client_mux)
        result = []
        self.mysql_client.handle_query(query, result)
        g_sync.munlock(self.mysql_client_mux)
        
        if result and result[0]:
            query_res_row = result[0][0]
            key = query_res_row[0]
            rand_num = query_res_row[1]
        else:
            g_utils.handle_type1_error(-1, "mysql_fetch_row error: hss_getautninfo")
    
    def handle_autninfo_req(self, conn_fd, pkt: Packet):
        """Handle authentication info request"""
        imsi = pkt.extract_item(int)
        plmn_id = pkt.extract_item(int)
        num_autn_vectors = pkt.extract_item(int)
        nw_type = pkt.extract_item(int)
        
        key = 0
        rand_num = 0
        self.get_autn_info(imsi, key, rand_num)
        
        print(f"hss_handleautoinforeq: retrieved from database: {imsi}")
        
        sqn = rand_num + 1
        xres = key + sqn + rand_num
        autn_num = xres + 1
        ck = xres + 2
        ik = xres + 3
        k_asme = ck + ik + sqn + plmn_id
        
        print(f"hss_handleautoinforeq: autn:{autn_num} rand:{rand_num} xres:{xres} k_asme:{k_asme} {imsi}")
        
        pkt.clear_pkt()
        pkt.append_item(autn_num)
        pkt.append_item(rand_num)
        pkt.append_item(xres)
        pkt.append_item(k_asme)
        pkt.prepend_diameter_hdr(1, pkt.len)
        self.server.snd(conn_fd, pkt)
        
        print(f"hss_handleautoinforeq: response sent to mme: {imsi}")
    
    def set_loc_info(self, imsi: int, mmei: int):
        """Set location information in database"""
        # Delete existing location info
        query = f"delete from loc_info where imsi = {imsi}"
        print(f"hss_setlocinfo: {query}")
        
        g_sync.mlock(self.mysql_client_mux)
        result = []
        self.mysql_client.handle_query(query, result)
        g_sync.munlock(self.mysql_client_mux)
        
        # Insert new location info
        query = f"insert into loc_info values({imsi}, {mmei})"
        print(f"hss_setlocinfo: {query}")
        
        g_sync.mlock(self.mysql_client_mux)
        result = []
        self.mysql_client.handle_query(query, result)
        g_sync.munlock(self.mysql_client_mux)
    
    def handle_location_update(self, conn_fd, pkt: Packet):
        """Handle location update request"""
        default_apn = 1
        imsi = pkt.extract_item(int)
        mmei = pkt.extract_item(int)
        
        self.set_loc_info(imsi, mmei)
        print("hss_handleautoinforeq: loc updated")
        
        pkt.clear_pkt()
        pkt.append_item(default_apn)
        pkt.prepend_diameter_hdr(2, pkt.len)
        self.server.snd(conn_fd, pkt)
        
        print("hss_handleautoinforeq: loc update complete sent to mme")

# Global HSS instance
g_hss = Hss()

def check_usage(argc: int):
    """Check command line usage"""
    if argc < 2:
        print("Usage: ./<hss_server_exec> THREADS_COUNT")
        g_utils.handle_type1_error(-1, "Invalid usage error: hssserver_checkusage")

def init(argv):
    """Initialize HSS server"""
    global g_workers_count
    g_workers_count = int(argv[1])
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

def run():
    """Run HSS server"""
    # MySQL connection
    g_hss.handle_mysql_conn()
    
    # HSS server
    print("HSS server started")
    g_hss.server.run(g_hss_ip_addr, g_hss_port, g_workers_count, handle_mme)

def handle_mme(conn_fd, worker_id: int) -> int:
    """Handle MME connection"""
    pkt = Packet()
    
    g_hss.server.rcv(conn_fd, pkt)
    if pkt.len <= 0:
        print("hssserver_handlemme: Connection closed")
        return 0
    
    pkt.extract_diameter_hdr()
    switch (pkt.diameter_hdr.msg_type):
        case 1:  # Authentication info req
            print("hssserver_handlemme: case 1: autn info req")
            g_hss.handle_autninfo_req(conn_fd, pkt)
            break
        
        case 2:  # Location update
            print("hssserver_handlemme: case 2: loc update")
            g_hss.handle_location_update(conn_fd, pkt)
            break
        
        default:  # For error handling
            print("hssserver_handlemme: default case:")
            break
    
    return 1

def finish():
    """Cleanup resources"""
    # MySQL cleanup handled by MySql destructor
    pass

def main(argc: int, argv):
    """Main function for HSS server"""
    check_usage(argc)
    init(argv)
    run()
    finish()
    return 0

if __name__ == "__main__":
    import sys
    main(len(sys.argv), sys.argv)