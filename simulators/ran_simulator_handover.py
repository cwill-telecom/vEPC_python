"""
RAN Simulator - Handover Simulation

"""

import time
import threading
from datetime import datetime
from typing import List
from ran import Ran, TrafficMonitor, g_ran_ip_addr, g_trafmon_ip_addr, g_trafmon_port, NUM_MONITORS
from utils import g_utils, CLOCK, MICROSECONDS
from sctp_server import SctpServer

# Global variables
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
g_traf_mon = TrafficMonitor()

# Handover specific globals
g_ran_sctp_ip_addr = "10.129.26.169"
g_ran_port = 4905
server = SctpServer()
ranS = Ran()  # Source ran for handover operation
ranT = Ran()  # Target ran for handover operation

def utraffic_monitor():
    """Uplink traffic monitor"""
    from udp_client import UdpClient
    sgw_s1_client = UdpClient()
    sgw_s1_client.set_client(g_trafmon_ip_addr)
    
    while True:
        g_traf_mon.handle_uplink_udata(sgw_s1_client)

def dtraffic_monitor():
    """Downlink traffic monitor"""
    while True:
        g_traf_mon.handle_downlink_udata()

def ping():
    """Ping function for RTT measurement"""
    cmd = "ping -I 172.16.1.3 172.16.0.2 -c 60 | grep \"^rtt\" >> ping.txt"
    print(cmd)
    import subprocess
    subprocess.run(cmd, shell=True)

def handle_mme_conn(conn_fd: int, dummy: int) -> int:
    """Handle all incoming MME connection for Handover purposes"""
    from packet import Packet
    
    res = False
    pkt = Packet()
    
    server.rcv(conn_fd, pkt)
    pkt.extract_s1ap_hdr()
    
    if pkt.s1ap_hdr.mme_s1ap_ue_id > 0:
        switch (pkt.s1ap_hdr.msg_type):
            case 7:  # Handover request
                print("Target Ran: handle handover request: case 7:")
                ranT.handle_handover(pkt)
                break
            
            case 8:  # Indirect tunnel from sgw
                print("Source Ran: receive indirect tunnel from sgw: case 8:")
                ranS.indirect_tunnel_complete(pkt)
                break
            
            case 9:  # Teardown request
                print("Source Ran to initiate a teardown for indirect teid: case 9:")
                ranS.request_tear_down(pkt)
                break
            
            default:  # For error handling
                print("ran_simulator_handle_mme: default case: handover")
                break
    
    return 1

def handover_traffic_monitor():
    """Handover traffic monitor"""
    server.run(g_ran_sctp_ip_addr, g_ran_port, 1, handle_mme_conn)

def simulateHandover():
    """Simulate handover between source and target RAN"""
    global ranS, ranT
    
    print("simulating.Handover between sRan and tRan")
    
    start_time = CLOCK.now()
    stop_time = CLOCK.now()
    time_diff_us = 0
    
    status = 0
    ran_num = 0
    ok = False
    
    ranS.handover_state = 0  # not in handover
    
    ranS.init(1)  # source enodeb initialization
    ranT.init(2)  # target enodeb initialization
    
    ranS.conn_mme()
    
    ranS.initial_attach()
    ok = ranS.authenticate()
    
    if not ok:
        print("ransimulator_simulate: autn failure")
    
    ok = ranS.set_security()
    
    if not ok:
        print("ransimulator_simulate: security setup failure")
    
    ok = ranS.set_eps_session(g_traf_mon)
    
    if not ok:
        print("ransimulator_simulate: eps session setup failure")
    
    # attach complete
    start_time = CLOCK.now()
    print("initiate Handover")
    ranS.initiate_handover()
    
    # sleep for some time to simulate disconnection and rejoining of UE to EnodeBs, then teardown
    time.sleep(0.5)  # 500ms sleep
    print("simulating UE disconnection/reconnection from enodeBs..")
    
    # here ranT signals that ue has connected to tRan and its ready to take over
    # this results in switching of downlink to target enodeb and tearing down of indirect tunnel
    ranT.complete_handover()
    
    # Stop time
    stop_time = CLOCK.now()
    
    # Response time
    time_diff_us = (stop_time - start_time).microseconds
    
    print("\n\n")
    print(f"Measured duration for handover between source ran to target ran {time_diff_us - 500000}")
    print(f"*****Handover Completed***** in {time_diff_us - 500000}ms")

def simulate(arg: int):
    """Basic simulation function (same as ran_simulator.py)"""
    ran = Ran()
    ran_num = arg
    time_exceeded = False
    
    ran.init(ran_num)
    ran.conn_mme()

    while True:
        # Run duration check
        g_utils.time_check(g_start_time, g_req_dur, [time_exceeded])
        if time_exceeded:
            break

        # Start time
        mstart_time = CLOCK.now()

        # Initial attach
        ran.initial_attach()

        # Authentication
        ok = ran.authenticate()
        if not ok:
            print(f"ransimulator_simulate: autn failure")
            return

        # Set security
        ok = ran.set_security()
        if not ok:
            print(f"ransimulator_simulate: security setup failure")
            return

        # Set eps session
        ok = ran.set_eps_session(g_traf_mon)
        if not ok:
            print(f"ransimulator_simulate: eps session setup failure")
            return

        # Data transfer
        ran.transfer_data(g_req_dur)

        # Detach
        ok = ran.detach()
        if not ok:
            print(f"ransimulator_simulate: detach failure")
            return

        # Stop time
        mstop_time = CLOCK.now()

        # Response time
        mtime_diff_us = (mstop_time - mstart_time).microseconds

        # Updating performance metrics
        g_sync.mlock(g_mux)
        global g_tot_regs, g_tot_regstime
        g_tot_regs += 1
        g_tot_regstime += mtime_diff_us
        g_sync.munlock(g_mux)

def check_usage(argc: int):
    """Check command line usage"""
    if argc < 3:
        print("Usage: ./<ran_simulator_exec> THREADS_COUNT DURATION")
        g_utils.handle_type1_error(-1, "Invalid usage error: ransimulator_checkusage")

def init(argv):
    """Initialize handover simulator"""
    global g_start_time, g_req_dur, g_tot_regs, g_tot_regstime
    global g_umon_thread, g_dmon_thread, g_threads
    
    g_start_time = time.time()
    g_req_dur = int(argv[2])
    g_tot_regs = 0
    g_tot_regstime = 0
    
    g_sync.mux_init(g_mux)
    g_umon_thread = [threading.Thread() for _ in range(NUM_MONITORS)]
    g_dmon_thread = [threading.Thread() for _ in range(NUM_MONITORS)]
    g_threads = [threading.Thread() for _ in range(2)]  # Only 2 threads for handover

def run():
    """Run the handover simulator"""
    global g_threads
    
    g_threads[0] = threading.Thread(target=handover_traffic_monitor)
    g_threads[1] = threading.Thread(target=simulateHandover)
    
    g_threads[0].start()
    g_threads[1].start()
    
    if g_threads[0].is_alive():
        g_threads[0].join()
    
    if g_threads[1].is_alive():
        g_threads[1].join()

def print_results():
    """Print simulation results"""
    global g_run_dur, g_start_time
    
    g_run_dur = time.time() - g_start_time
    
    print("\n\n")
    print("Requested duration has ended. Finishing the program.")

def main(argc: int, argv):
    """Main function"""
    check_usage(argc)
    init(argv)
    run()
    print_results()
    return 0

if __name__ == "__main__":
    import sys
    main(len(sys.argv), sys.argv)