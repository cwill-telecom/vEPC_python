"""
RAN Simulator - Basic UE Simulation

"""

import time
import threading
from datetime import datetime
from typing import List
from ran import Ran, TrafficMonitor, g_ran_ip_addr, g_trafmon_ip_addr, g_trafmon_port, NUM_MONITORS
from utils import g_utils, CLOCK, MICROSECONDS

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

def simulate(arg: int):
    """Main simulation function for UE"""
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

        # To find RTT
        if ran_num == 0:
            global g_rtt_thread
            g_rtt_thread = threading.Thread(target=ping)
            g_rtt_thread.start()

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
    """Initialize simulator"""
    global g_start_time, g_threads_count, g_req_dur, g_tot_regs, g_tot_regstime
    global g_umon_thread, g_dmon_thread, g_threads
    
    g_start_time = time.time()
    g_threads_count = int(argv[1])
    g_req_dur = int(argv[2])
    g_tot_regs = 0
    g_tot_regstime = 0
    
    g_sync.mux_init(g_mux)
    g_umon_thread = [threading.Thread() for _ in range(NUM_MONITORS)]
    g_dmon_thread = [threading.Thread() for _ in range(NUM_MONITORS)]
    g_threads = [threading.Thread() for _ in range(g_threads_count)]

def run():
    """Run the simulator"""
    global g_umon_thread, g_dmon_thread, g_threads
    
    # Tun
    g_traf_mon.tun.set_itf("tun1", "172.16.0.1/16")
    g_traf_mon.tun.conn("tun1")

    # Traffic monitor server
    print("Traffic monitor server started")
    from udp_server import UdpServer
    g_traf_mon.server = UdpServer()
    g_traf_mon.server.run(g_trafmon_ip_addr, g_trafmon_port)

    # Uplink traffic monitor
    for i in range(NUM_MONITORS):
        g_umon_thread[i] = threading.Thread(target=utraffic_monitor)
        g_umon_thread[i].start()

    # Downlink traffic monitor
    for i in range(NUM_MONITORS):
        g_dmon_thread[i] = threading.Thread(target=dtraffic_monitor)
        g_dmon_thread[i].start()

    # Simulator threads
    for i in range(g_threads_count):
        g_threads[i] = threading.Thread(target=simulate, args=(i,))
        g_threads[i].start()

    # Join all threads
    for i in range(g_threads_count):
        if g_threads[i].is_alive():
            g_threads[i].join()

def print_results():
    """Print simulation results"""
    global g_run_dur, g_tot_regs, g_tot_regstime, g_start_time
    
    g_run_dur = time.time() - g_start_time
    
    print("\n\n")
    print("Requested duration has ended. Finishing the program.")
    print(f"Total number of registrations is {g_tot_regs}")
    print(f"Total time for registrations is {g_tot_regstime * 1e-6} seconds")
    print(f"Total run duration is {g_run_dur} seconds")
    if g_tot_regs > 0:
        print(f"Latency is {((g_tot_regstime/g_tot_regs) * 1e-6)} seconds")
        print(f"Throughput is {((g_tot_regs/g_run_dur))}")

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