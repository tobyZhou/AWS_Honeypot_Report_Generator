
# Local modules
from base_packet import BasePacket


class IcmpPacket(BasePacket):
    def __init__(self, src_ip="", dst_ip="", packet_size=0, country="", city="", icmp_type=-1, timestamp=0,
                 network_prtcl="", transport_prtcl="", application_prtcl=""):
        BasePacket.__init__(self, src_ip, dst_ip, packet_size, country, city, timestamp, network_prtcl,
                            transport_prtcl, application_prtcl)
        self.icmp_type = icmp_type

    def get_icmp_type(self):
        return self.icmp_type
