
# Local modules
from base_packet import BasePacket


class TcpPacket(BasePacket):
    def __init__(self, src_ip="", src_port=-1, dst_ip="", dst_port=-1, packet_size=0, country="", city="", timestamp=0,
                 network_prtcl="", transport_prtcl="", application_prtcl=""):
        BasePacket.__init__(self, src_ip, dst_ip, packet_size, country, city, timestamp, network_prtcl,
                            transport_prtcl, application_prtcl)
        self.src_port = src_port
        self.dst_port = dst_port

    def get_src_port(self):
        return self.src_port

    def get_dst_port(self):
        return self.dst_port
