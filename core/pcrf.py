"""
vPCRF - Policy and Charging Rules Function implementation

Part of the Affirmed Lab SCHA M2M vEPC. Serves the Gx interface used by
both M2M vPGW1 and IoT/pLTE vPGW2 (the two Gx arrows converging on vPCRF
in the diagram) and returns a PCC rule name per session based on which
vPGW/APN the request came from.

Usage:
    python3 pcrf.py THREADS_COUNT
"""

import signal
from typing import Dict
from diameter import Diameter
from packet import Packet
from udp_server import UdpServer
from utils import g_utils

# Global configuration
g_pcrf_ip_addr = "10.129.26.169"
g_pcrf_gx_port = 9000

GX_CCR = 3   # Credit Control Request  (vPGW -> vPCRF)
GX_CCA = 4   # Credit Control Answer   (vPCRF -> vPGW)

g_workers_count = 0

# Static PCC rule table, keyed by the "role" the requesting vPGW reports
# over Gx. Mirrors the two vPGWs fronted by vPCRF in the diagram.
PCC_RULES = {
    "m2m": "pcc-rule-m2m-default",
    "iot": "pcc-rule-iot-plte-lowrate",
}


class Pcrf:
    """Policy and Charging Rules Function (PCRF) implementation"""

    def __init__(self):
        self.server = UdpServer()
        self.sessions: Dict[int, str] = {}  # imsi -> pcc rule in force

    def handle_ccr(self, src_sock_addr: Dict, pkt: Packet):
        """Handle a Gx Credit Control Request from a vPGW"""
        imsi = pkt.extract_item(int)
        apn_in_use = pkt.extract_item(int)
        role = pkt.extract_item(str)

        pcc_rule = PCC_RULES.get(role, "pcc-rule-default")
        self.sessions[imsi] = pcc_rule
        print(f"pcrf_handleccr: imsi={imsi} apn={apn_in_use} role={role} -> {pcc_rule}")

        pkt.clear_pkt()
        pkt.append_item(pcc_rule)
        pkt.prepend_diameter_hdr(GX_CCA, pkt.len)
        self.server.snd(src_sock_addr, pkt)


# Global PCRF instance
g_pcrf = Pcrf()


def check_usage(argc: int):
    """Check command line usage"""
    if argc < 2:
        print("Usage: ./<pcrf_server_exec> THREADS_COUNT")
        g_utils.handle_type1_error(-1, "Invalid usage error: pcrfserver_checkusage")


def init(argv):
    """Initialize vPCRF server"""
    global g_workers_count
    g_workers_count = int(argv[1])
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)


def run():
    """Run vPCRF Gx server, servicing both vPGW1 and vPGW2"""
    print("vPCRF Gx server started (serving M2M vPGW1 and IoT/pLTE vPGW2)")
    g_pcrf.server.run(g_pcrf_ip_addr, g_pcrf_gx_port)

    src_sock_addr = {}
    pkt = Packet()
    while True:
        g_pcrf.server.rcv(src_sock_addr, pkt)
        pkt.extract_diameter_hdr()

        if pkt.diameter_hdr.msg_type == GX_CCR:
            g_pcrf.handle_ccr(src_sock_addr, pkt)
        else:
            print(f"pcrfserver_run: unexpected Gx msg_type {pkt.diameter_hdr.msg_type}")


def main(argc: int, argv):
    """Main function for vPCRF server"""
    check_usage(argc)
    init(argv)
    run()
    return 0


if __name__ == "__main__":
    import sys
    main(len(sys.argv), sys.argv)
