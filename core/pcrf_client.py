"""
Gx client helper used by M2M vPGW1 and IoT/pLTE vPGW2 to reach vPCRF.

Both vPGWs in the diagram have a Gx link to the same vPCRF. This class
wraps that Diameter/Gx exchange (Credit Control Request/Answer) so pgw.py
can request PCC rules for a session with a single call.
"""

from diameter import Diameter
from packet import Packet
from udp_client import UdpClient

# Gx message types (carried in the Diameter header's msg_type field)
GX_CCR = 3   # Credit Control Request  (vPGW -> vPCRF)
GX_CCA = 4   # Credit Control Answer   (vPCRF -> vPGW)


class PcrfClient:
    """Gx client towards vPCRF"""

    def __init__(self, role: str = "m2m"):
        self.role = role  # "m2m" (vPGW1) or "iot" (vPGW2)
        self.client = UdpClient()

    def request_pcc_rules(self, imsi: int, apn_in_use: int, pcrf_ip_addr: str, pcrf_gx_port: int):
        """Send a Gx CCR for this session and return the PCC rule name.

        In the diagram this is the Gx link from M2M vPGW1 / IoT-pLTE vPGW2
        up to vPCRF, used to fetch the QoS/charging rule that should be
        applied before the session is admitted.
        """
        pkt = Packet()
        pkt.clear_pkt()
        pkt.append_item(imsi)
        pkt.append_item(apn_in_use)
        pkt.append_item(self.role)
        pkt.prepend_diameter_hdr(GX_CCR, pkt.len)

        self.client.set_server(pcrf_ip_addr, pcrf_gx_port)
        self.client.snd(pkt)
        self.client.rcv(pkt)

        pkt.extract_diameter_hdr()
        pcc_rule = pkt.extract_item(str)
        return pcc_rule
