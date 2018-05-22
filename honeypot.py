
# Modules
import os
import sys
from collections import Counter
from pcapng import FileScanner
from pcapng.blocks import EnhancedPacket
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, ICMP

# Local modules
import config
import utility
from tcp_packet import TcpPacket
from icmp_packet import IcmpPacket


# Strings
Log_Folder_Miss_Warning = "Log directory for Honeypot {} is not found. Please check!"


class Honeypot:
    def __init__(self, name="", ip="", date="", log_folder=""):
        self.name = name
        self.ip = ip
        self.date = date

        self.log_folder = log_folder
        if not self.log_folder:
            self.log_folder = os.path.join(config.Parent_Folder, self.name)
            if not os.path.isdir(self.log_folder):
                print Log_Folder_Miss_Warning.format(self.name)
                sys.exit(0)

        self.log_files = []
        for log_name in os.listdir(self.log_folder):
            if date in log_name and "pcap" in log_name:
                log_path = os.path.join(self.log_folder, log_name)
                if os.path.isfile(log_path):
                    self.log_files.append(log_path)

        # Counter for both TCP and ICMP
        self.tcp_num_counter = Counter()    # key is "port:hour"
        self.tcp_size_counter = Counter()   # key is "port:hour"
        self.tcp_country_counter = Counter()  # key is "port:country"
        self.tcp_countries = []
        self.tcp_packets = []

        self.icmp_num_counter = Counter()    # key is "ICMP type:hour"
        self.icmp_size_counter = Counter()   # key is "ICMP type:hour"
        self.icmp_country_counter = Counter()  # key is "ICMP type:country"
        self.icmp_countries = []
        self.icmp_packets = []

    def process_pcaps(self):
        for logfile in self.log_files:
            # Get hour info from file name
            # File format is: yyyymmdd-hh.pcap (MUST update when format changed!!)
            print "Procssing: ", logfile
            hour = (logfile.split('.')[-2]).split('-')[-1]
            hour = str(int(hour))  # remove head '0'

            fp = open(logfile, "rb")
            scan_result = FileScanner(fp)

            # Load protocol info from csv file
            csv_file = '.'.join(logfile.split('.')[:-1]) + ".csv"
            if not os.path.isfile(csv_file):
                utility.convert_pcap_to_csv(logfile, csv_file)
            protocol_list = utility.load_protocols(csv_file)
            #print protocol_list

            block_index = 0  # used for matching protocol list
            for block in scan_result:
                if not isinstance(block, EnhancedPacket):
                    continue
                assert block.interface.link_type == 1  # must be ethernet!

                decoded = Ether(block.packet_data)
                _pl1 = decoded.payload
                timestamp = int(block.timestamp)  # convert float to int to remove second fractions
                if isinstance(_pl1, IP):
                    # Only when packet is sent to this honeypot
                    if _pl1.dst == self.ip:
                        _pl2 = _pl1.payload

                        # Currently only filter TCP and ICMP packets
                        if isinstance(_pl2, TCP) and hasattr(_pl2, "dport"):
                            port = _pl2.dport
                            if port in config.TCP_Checking_Ports:
                                # Process number, size counter for tcp
                                key = "{}:{}".format(str(port), hour)
                                self.tcp_num_counter[key] += 1
                                self.tcp_size_counter[key] += block.packet_len

                                # Process country counter for tcp
                                country, city = utility.get_ip_country_city(_pl1.src)
                                key = "{}:{}".format(str(port), country)
                                self.tcp_country_counter[key] += 1
                                if country not in self.tcp_countries:
                                    self.tcp_countries.append(country)

                                # Get application layer protocol if avail
                                app_prtcl = protocol_list[block_index]
                                if app_prtcl.lower() == "tcp" or app_prtcl.lower() == "icmp":
                                    app_prtcl = "None"

                                # Create tcp packet object
                                tcp_packet = TcpPacket(src_ip=_pl1.src,
                                                       src_port=_pl2.sport,
                                                       dst_ip=_pl1.dst,
                                                       dst_port=_pl2.dport,
                                                       packet_size=block.packet_len,
                                                       country=country,
                                                       city=city,
                                                       timestamp=timestamp,
                                                       network_prtcl="IP",
                                                       transport_prtcl="TCP",
                                                       application_prtcl=app_prtcl)
                                self.tcp_packets.append(tcp_packet)

                        elif isinstance(_pl2, ICMP) and hasattr(_pl2, "type"):
                            icmp_type = _pl2.type
                            if icmp_type in config.ICMP_Checking_Types:
                                # Process number, size counter for icmp
                                key = "{}:{}".format(str(icmp_type), hour)
                                self.icmp_num_counter[key] += 1
                                self.icmp_size_counter[key] += block.packet_len

                                # Process country counter for icmp
                                country, city = utility.get_ip_country_city(_pl1.src)
                                key = "{}:{}".format(str(icmp_type), country)
                                self.icmp_country_counter[key] += 1
                                if country not in self.icmp_countries:
                                    self.icmp_countries.append(country)

                                # Get application layer protocol if avail
                                app_prtcl = protocol_list[block_index]
                                if app_prtcl.lower() == "tcp" or app_prtcl.lower() == "icmp":
                                    app_prtcl = "None"

                                # Create icmp packet object
                                icmp_packet = IcmpPacket(src_ip=_pl1.src,
                                                         dst_ip=_pl1.dst,
                                                         packet_size=block.packet_len,
                                                         country=country,
                                                         city=city,
                                                         icmp_type=_pl2.type,
                                                         timestamp=timestamp,
                                                         network_prtcl="IP",
                                                         transport_prtcl="ICMP",
                                                         application_prtcl=app_prtcl)
                                self.icmp_packets.append(icmp_packet)

                block_index += 1

            fp.close()

    def get_ip(self):
        return self.ip

    def get_log_folder(self):
        return self.log_folder

    def get_tcp_num_counter(self):
        return self.tcp_num_counter

    def get_tcp_size_counter(self):
        return self.tcp_size_counter

    def get_tcp_country_counter(self):
        return self.tcp_country_counter

    def get_tcp_countries(self):
        return self.tcp_countries

    def get_tcp_packets(self):
        return self.tcp_packets

    def get_icmp_num_counter(self):
        return self.icmp_num_counter

    def get_icmp_size_counter(self):
        return self.icmp_size_counter

    def get_icmp_country_counter(self):
        return self.icmp_country_counter

    def get_icmp_countries(self):
        return self.icmp_countries

    def get_icmp_packets(self):
        return self.icmp_packets
