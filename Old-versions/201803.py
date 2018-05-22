#!/usr/bin/env python

'''
    This script is for AWS data
    1. only consider TCP and ICMP
'''

import os, sys
import datetime
from collections import Counter

from pcapng import FileScanner
from pcapng.blocks import EnhancedPacket

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, ICMP

import geoip2.database

# Configs
Threshold_Tcp_Num = 100
Threshold_Tcp_Average_Size = 100

# Configurations:  Variables that may need to add, modify or delete
Honeypot_IP_Name_Map = {"172.31.1.17": "ADSC_0",
                        "172.31.27.32": "ADSC_1",
                        "172.31.13.26": "ADSC_2",
                        "172.31.42.31": "ADSC_3",
                        "172.31.20.47": "ADSC_4"}
AWS_honeypot_ips = ["172.31.1.17", "172.31.27.32", "172.31.13.26",
                    "172.31.42.31", "172.31.20.47"]
TCP_Checking_Ports = [502, 1911, 4911, 2222, 44818, 47808, 19999,
                      20000, 102, 2404, 8333]
ICMP_Checking_Types = [8]

# Used strings
Log_Folder_Miss_Warning = "Log directory for Honeypot {} is not found. Please check!"
IP_Database_File = "GeoLite2-City_20171107/GeoLite2-City.mmdb"

Report_Directory_Name = "Daily_Reports"

HTML_Name_Format = "{}-{}.html"  # date-type. Eg: 20171201-tcp.html
CSV_Name_Format = "{}-{}.csv"
JSON_Name_Format = "{}-{}.json"

Source_IP_Index = 0
Source_Country_Index = 1
Source_City_Index = 2
Source_Ports_Index = 3

Yellow_Color = "#F4B942"
Orange_Color = "#E84629"


class BasicPacket:
    def __init__(self, src_ip="", dst_ip="", packet_size=0, country="", city="", timestamp=0):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.packet_size = packet_size
        self.country = country
        self.city = city
        if not self.country:
            self.country, self.city = get_ip_country_city(self.src_ip)
        self.timestamp = timestamp

    def get_src_ip(self):
        return self.src_ip

    def get_dst_ip(self):
        return self.dst_ip

    def get_packet_size(self):
        return self.packet_size

    def get_src_country(self):
        return self.country

    def get_src_city(self):
        return self.city

    def get_src_country_city(self):
        return self.get_src_country(), self.get_src_city()

    def get_timestamp(self):
        return self.timestamp

class TcpPacket(BasicPacket):
    def __init__(self, src_ip="", src_port=-1, dst_ip="", dst_port=-1, packet_size=0, country="", city="", timestamp=0):
        BasicPacket.__init__(self, src_ip, dst_ip, packet_size, country, city, timestamp)
        self.src_port = src_port
        self.dst_port = dst_port

    def get_src_port(self):
        return self.dst_port

    def get_dst_port(self):
        return self.dst_port

class IcmpPacket(BasicPacket):
    def __init__(self, src_ip="", dst_ip="", packet_size=0, country="", city="", icmp_type=-1, timestamp=0):
        BasicPacket.__init__(self, src_ip, dst_ip, packet_size, country, city, timestamp)
        self.icmp_type = icmp_type

    def get_icmp_type(self):
        return self.icmp_type


class Honeypot:
    def __init__(self, name="", ip="", date="", log_folder=""):
        self.name = name
        self.ip = ip
        self.date = date

        self.log_folder = log_folder
        if not self.log_folder:
            parent_dir = os.path.dirname(os.getcwd())
            self.log_folder = os.path.join(parent_dir, self.name)
            if not os.path.isdir(self.log_folder):
                print Log_Folder_Miss_Warning.format(self.name)
                return

        self.log_files = []
        for log_name in os.listdir(self.log_folder):
            if date in log_name:
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
            hour = str(int(hour)) # remove head '0'

            fp = open(logfile, "rb")
            scan_result = FileScanner(fp)

            for block in scan_result:
                if not isinstance(block, EnhancedPacket):
                    continue
                assert block.interface.link_type == 1  # must be ethernet!

                decoded = Ether(block.packet_data)
                _pl1 = decoded.payload
                timestamp = int(block.timestamp) # convert float to int to remove second fractions
                if isinstance(_pl1, IP):
                    # Only when packet is sent to this honeypot
                    if _pl1.dst == self.ip:
                        _pl2 = _pl1.payload

                        # Currently only filter TCP and ICMP packets
                        if isinstance(_pl2, TCP) and hasattr(_pl2, "dport"):
                            port = _pl2.dport
                            if port in TCP_Checking_Ports:
                                # Process number, size counter for tcp
                                key = "{}:{}".format(str(port), hour)
                                self.tcp_num_counter[key] += 1
                                self.tcp_size_counter[key] += block.packet_len

                                # Process country counter for tcp
                                country, city = get_ip_country_city(_pl1.src)
                                key = "{}:{}".format(str(port), country)
                                self.tcp_country_counter[key] += 1
                                if country not in self.tcp_countries:
                                    self.tcp_countries.append(country)

                                # Create tcp packet object
                                tcp_packet = TcpPacket(src_ip=_pl1.src, src_port=_pl2.sport, dst_ip=_pl1.dst,
                                    dst_port=_pl2.dport, packet_size=block.packet_len, country=country, city=city,
                                    timestamp = timestamp)
                                self.tcp_packets.append(tcp_packet)

                        elif isinstance(_pl2, ICMP) and hasattr(_pl2, "type"):
                            icmp_type = _pl2.type
                            if icmp_type in ICMP_Checking_Types:
                                # Process number, size counter for icmp
                                key = "{}:{}".format(str(icmp_type), hour)
                                self.icmp_num_counter[key] += 1
                                self.icmp_size_counter[key] += block.packet_len

                                # Process country counter for icmp
                                country, city = get_ip_country_city(_pl1.src)
                                key = "{}:{}".format(str(icmp_type), country)
                                self.icmp_country_counter[key] += 1
                                if country not in self.icmp_countries:
                                    self.icmp_countries.append(country)

                                # Create icmp packet object
                                icmp_packet = IcmpPacket(src_ip=_pl1.src, dst_ip=_pl1.dst, packet_size=block.packet_len,
                                    country=country, city=city, icmp_type=_pl2.type, timestamp=timestamp)
                                self.icmp_packets.append(icmp_packet)

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


# Get input date from user in following two formats
# 1. date format - yyyymmdd
# 2. keyword: yesterday & today
def get_input_date():
    if (len(sys.argv) != 2):
        print "1. Please input a date format - yyyymmdd. Eg: 20171101"
        print "2. Please indicate date. Currently only support yesterday & today"
        sys.exit(0)
    
    date = sys.argv[1]

    if date.lower() == "yesterday":
        yesterday = datetime.datetime.now() - datetime.timedelta(days=1)
        date = yesterday.strftime("%Y%m%d")
    elif date.lower() == "today":
        today = datetime.datetime.now()
        date = today.strftime("%Y%m%d")
    else:
        # if not yesterday or today, then must be yyyymmdd format
        if (len(date) != 8):
            print "Invalid format. Please follow yyyymmdd. Eg: 20171202"
            print "Or indicate yesterday/today alternatively."
            sys.exit(0)
    
        try:
            datetime.datetime.strptime(date, "%Y%m%d")
        except ValueError:
            print "Invalid format. Please follow yyyymmdd. Eg: 20171203"
            print "Or indicate yesterday/today alternatively."
            sys.exit(0)
    
    return date


# Found out the country and city information based in ip address
def get_ip_country_city(ip):
    if not ip:
        return "None", "None"

    ip_reader = geoip2.database.Reader(IP_Database_File)
    try:
        response = ip_reader.city(ip)
        if response.country.name and response.city.name:
            return (response.country.name).encode('utf-8'), (response.city.name).encode('utf-8')
        elif response.country.name and not response.city.name:
            return (response.country.name).encode('utf-8'), "None"
        elif not response.country.name and response.city.name:
            return "None", (response.city.name).encode('utf-8')
        else:
            return "None", "None"
    except:
        return "None", "None"


# Helper functions for generating html, csv, json files
def get_report_directory():
    parent_dir = os.path.dirname(os.getcwd())
    report_dir = os.path.join(parent_dir, Report_Directory_Name)
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
    return report_dir


# Helper functions for generating html, csv, json files
def human_number(num, k=1000):
    powers = [''] + list('kMGTPEY')
    assert isinstance(num, (int, long))
    for i, suffix in enumerate(powers):
        if (num < (k ** (i + 1))) or (i == len(powers) - 1):
            return '{0:d}{1}'.format(int(round(num / (k ** i))), suffix)
    raise AssertionError('Should never reach this')


def generate_html_files(date, honeyports):
    print "Generating htmls"
    generate_html_tcp_file(date, honeyports)
    generate_html_icmp_file(date, honeyports)


def generate_html_tcp_file(date, honeypots):
    html_tcp_content = "<html>"
    html_tcp_content += r"<header><h2>Date: {}-{}-{}</h2></header><br/>". \
                        format(date[0:4], date[4:6], date[6:8])
    for hp in honeypots:
        html_tcp_content += r"<header><h3>{}:  {}</h3></header>".\
                            format(hp.get_ip(), hp.get_log_folder())

        # Table for port-hour
        html_tcp_content += r"<body><p>Port-Hour Table</p><table border='1'>"
        html_tcp_content += r"<tr><td>Port</td><td></td>"
        for i in range(0, 24):
            html_tcp_content += r"<td width=50>{}H</td>".format(str(i))
        html_tcp_content += r"<td>Daily</td><td>Average Size</td></tr>"

        tcp_num_counter = hp.get_tcp_num_counter()
        tcp_size_counter = hp.get_tcp_size_counter()
        for port in TCP_Checking_Ports:
            daily_num = 0
            daily_size = 0
            num_row = r"<tr><td>{}</td><td>number</td>".format(str(port))
            size_row = r"<tr><td></td><td>size</td>"

            for hour in range(0, 24):
                key = r"{}:{}".format(str(port), str(hour))
                num = tcp_num_counter[key]
                size = tcp_size_counter[key]
                daily_num += num
                daily_size += size
                if num != 0:
                    num_row += r"<td width=50 bgcolor='{}'>{}</td>".\
                                format(Yellow_Color, str(num))
                    size_row += r"<td width=50 bgcolor='{}'>{}B</td>".\
                                format(Yellow_Color, human_number(size, 1024))
                else:
                    num_row += r"<td width=50>{}</td>".format(str(num))
                    size_row += r"<td width=50>{}</td>".format(human_number(size, 1024))

            if daily_num != 0:
                if daily_num > Threshold_Tcp_Num:
                    bg_color = Orange_Color
                else:
                    bg_color = Yellow_Color
                num_row += r"<td width=50 bgcolor='{}'>{}</td><td>-</td></tr>".\
                            format(bg_color, str(daily_num))

                if int(daily_size/daily_num) > Threshold_Tcp_Average_Size:
                    bg_color = Orange_Color
                else:
                    bg_color = Yellow_Color
                size_row += r"<td width=50 bgcolor='{}'>{}B</td><td bgcolor='{}'>{}B</td></tr>".\
                            format(Yellow_Color, human_number(daily_size, 1024), bg_color, daily_size/daily_num)
            else:
                num_row += r"<td width=50>{}</td><td>-</td></tr>".format(str(daily_num))
                size_row += r"<td width=50>{}</td><td>0</td></tr>".format(human_number(daily_size, 1024))

            html_tcp_content += num_row
            html_tcp_content += size_row
        html_tcp_content += r"</table></body>"

        # Table for port-country
        html_tcp_content += r"<br/><p>Port-Country Table</p><body><table border='1'>"
        country_counter = hp.get_tcp_country_counter()
        countries = sorted(hp.get_tcp_countries())
        html_tcp_content += r"<tr><td>Port</td><td>{}</td></tr>".format(r"</td><td>".join(countries))
        for port in TCP_Checking_Ports:
            country_row = r"<tr><td>{}</td>".format(str(port))
            for country in countries:
                key = r"{}:{}".format(str(port), country)
                country_num = country_counter[key]
                if country_num != 0:
                    country_row += r"<td width=50 bgcolor='#F4B942'>{}</td>". \
                                   format(str(country_num))
                else:
                    country_row += r"<td width=50>{}</td>".format(str(country_num))
            country_row += r"</tr>"
            html_tcp_content += country_row
        html_tcp_content += r"</table></body>"

        html_tcp_content += r"<p>Source IPs: </p>"
        sorted_info = process_ip_country_port_info(hp.get_tcp_packets())
        sorted_info.sort(key=lambda x: x[Source_Country_Index])
        for entry in sorted_info:
            line = "{} - {}, {} - Access port: ".format(entry[Source_IP_Index], \
                   entry[Source_Country_Index], entry[Source_City_Index])
            for p in entry[Source_Ports_Index]:
                line += str(p) + "  "
            html_tcp_content += r"<p>{}</p>".format(line)

        html_tcp_content += r"<br/>"
    html_tcp_content += "</html>"

    # Write to file
    report_dir = get_report_directory()
    html_tcp_file = os.path.join(report_dir, HTML_Name_Format.format(date, "tcp"))
    with open(html_tcp_file, "w+") as fp:
        fp.write(html_tcp_content)


def generate_html_icmp_file(date, honeyports):
    html_icmp_content = "<html>"
    html_icmp_content += r"<header><h2>Date: {}-{}-{}</h2></header><br/>". \
                         format(date[0:4], date[4:6], date[6:8])
    for hp in honeyports:
        html_icmp_content += r"<header><h3>{}:  {}</h3></header>". \
                             format(hp.get_ip(), hp.get_log_folder())

        # Table for port-hour
        html_icmp_content += r"<body><p>Icmp Type-Hour Table</p><table border='1'>"
        html_icmp_content += r"<tr><td>Type</td><td></td>"
        for i in range(0, 24):
            html_icmp_content += r"<td width=50>{}H</td>".format(str(i))
        html_icmp_content += r"<td>Daily</td></tr>"

        icmp_num_counter = hp.get_icmp_num_counter()
        icmp_size_counter = hp.get_icmp_size_counter()
        for type in ICMP_Checking_Types:
            daily_num = 0
            daily_size = 0
            num_row = r"<tr><td>{}</td><td>number</td>".format(str(type))
            size_row = r"<tr><td></td><td>size</td>"

            for hour in range(0, 24):
                key = r"{}:{}".format(str(type), str(hour))
                num = icmp_num_counter[key]
                size = icmp_size_counter[key]
                daily_num += num
                daily_size += size
                if num != 0:
                    num_row += r"<td width=50 bgcolor='#F4B942'>{}</td>". \
                        format(str(num))
                    size_row += r"<td width=50 bgcolor='#F4B942'>{}B</td>". \
                        format(human_number(size, 1024))
                else:
                    num_row += r"<td width=50>{}</td>".format(str(num))
                    size_row += r"<td width=50>{}</td>".format(human_number(size, 1024))

            if daily_num !=0:
                num_row += r"<td width=50 bgcolor='#F4B942'>{}</td></tr>". \
                    format(str(daily_num))
                size_row += r"<td width=50 bgcolor='#F4B942'>{}B</td></tr>". \
                    format(human_number(daily_size, 1024))
            else:
                num_row += r"<td width=50>{}</td></tr>".format(str(daily_num))
                size_row += r"<td width=50>{}</td></tr>".format(human_number(daily_size, 1024))

            html_icmp_content += num_row
            html_icmp_content += size_row
        html_icmp_content += r"</table></body>"

        # Table for icmp type - country
        html_icmp_content += r"<br/><p>Icmp Type-Country Table</p><body><table border='1'>"
        country_counter = hp.get_icmp_country_counter()
        countries = sorted(hp.get_icmp_countries())
        html_icmp_content += r"<tr><td>Type</td><td>{}</td></tr>".format(r"</td><td>".join(countries))
        for type in ICMP_Checking_Types:
            country_row = r"<tr><td>{}</td>".format(str(type))
            for country in countries:
                key = r"{}:{}".format(str(type), country)
                country_num = country_counter[key]
                if country_num != 0:
                    country_row += r"<td width=50 bgcolor='#F4B942'>{}</td>". \
                                   format(str(country_num))
                else:
                    country_row += r"<td width=50>{}</td>".format(str(country_num))
            country_row += r"</tr>"
            html_icmp_content += country_row
        html_icmp_content += r"</table></body>"

        html_icmp_content += r"<p>Source IPs: </p>"
        sorted_info = process_icmp_ip_info(hp.get_icmp_packets())
        sorted_info.sort(key=lambda x: x[Source_Country_Index])
        for entry in sorted_info:
            line = "{} - {}, {}".format(entry[Source_IP_Index], \
                   entry[Source_Country_Index], entry[Source_City_Index])
            html_icmp_content += r"<p>{}</p>".format(line)

        html_icmp_content += r"<br/><br/>"

    html_icmp_content += "</html>"

    # Write to file
    report_dir = get_report_directory()
    html_icmp_file = os.path.join(report_dir, HTML_Name_Format.format(date, "icmp"))
    with open(html_icmp_file, "w+") as fp:
        fp.write(html_icmp_content)


def process_icmp_ip_info(packet_list):
    info = []
    for packet in packet_list:
        ip = packet.get_src_ip()
        country, city = packet.get_src_country_city()

        exist_ip = False
        for index, entry in enumerate(info):
            if entry[Source_IP_Index] == ip:
                exist_ip = True
                break

        if not exist_ip:
            info.append([ip, country, city])

    return info


def process_ip_country_port_info(packet_list):
    info = []
    for packet in packet_list: # tcp packets only
        ip = packet.get_src_ip()
        country, city = packet.get_src_country_city()
        port = packet.get_dst_port()

        exist_ip = False
        for index, entry in enumerate(info):
            if entry[Source_IP_Index] == ip:
                exist_ip = True
                if port not in entry[Source_Ports_Index]:
                    info[index][Source_Ports_Index].append(port)

        if not exist_ip:
            info.append([ip, country, city, [port]])

    return info


def generate_csv_files(date, honeyports):
    print "Generating CSVs"
    generate_csv_tcp_file(date, honeyports)
    generate_csv_icmp_file(date, honeyports)


def generate_csv_icmp_file(date, honeyports):
    csv_icmp_content = "Date, {}-{}-{}\n\n".format(date[0:4], date[4:6], date[6:8])
    for hp in honeyports:
        csv_icmp_content += "{}, {}\n".format(hp.get_ip(), hp.get_log_folder())

        # Type - Hour Table
        csv_icmp_content += "\nICMP Type-Hour Table\n"
        csv_icmp_content += "Type,,"
        for i in range(0, 24):
            csv_icmp_content += "{}H,".format(str(i))
        csv_icmp_content += "Daily\n"

        icmp_num_counter = hp.get_icmp_num_counter()
        icmp_size_counter = hp.get_icmp_size_counter()
        for type in ICMP_Checking_Types:
            num_row = "{},number,".format(str(type))
            size_row = ",size,"
            daily_num = 0
            daily_size = 0

            for hour in range(0, 24):
                key = "{}:{}".format(str(type), str(hour))
                num = icmp_num_counter[key]
                size = icmp_size_counter[key]
                daily_num += num
                daily_size += size
                num_row += "{},".format(str(num))
                if num != 0:
                    size_row += "{}B,".format(human_number(size, 1024))
                else:
                    size_row += "{},".format(human_number(size, 1024))

            num_row += "{}\n".format(str(daily_num))
            if daily_num != 0:
                size_row += "{}B\n".format(human_number(daily_size, 1024))
            else:
                size_row += "{}\n".format(human_number(daily_size, 1024))

            csv_icmp_content += num_row
            csv_icmp_content += size_row

        # Type - Country Table
        csv_icmp_content += "\nICMP Type-Country Table\n"
        icmp_country_counter = hp.get_icmp_country_counter()
        countries = sorted(hp.get_icmp_countries())
        csv_icmp_content += "Type," + ",".join(countries) + "\n"
        for type in ICMP_Checking_Types:
            country_row = r"{},".format(str(type))
            for country in countries:
                key = r"{}:{}".format(str(type), country)
                country_row += "{},".format(str(icmp_country_counter[key]))
            country_row += "\n"
            csv_icmp_content += country_row

        # Source IPs
        csv_icmp_content += "Source IPs,Country-City\n"
        sorted_info = process_icmp_ip_info(hp.get_icmp_packets())
        sorted_info.sort(key=lambda x: x[Source_Country_Index])
        for entry in sorted_info:
            line = "{}, {}-{},".format(entry[Source_IP_Index], \
                                    entry[Source_Country_Index], entry[Source_City_Index])
            csv_icmp_content += line + "\n"

        csv_icmp_content += "\n\n"

    # Write to file
    report_dir = get_report_directory()
    csv_icmp_file = os.path.join(report_dir, CSV_Name_Format.format(date, "icmp"))
    with open(csv_icmp_file, "w+") as fp:
        fp.write(csv_icmp_content)


def generate_csv_tcp_file(date, honeyports):
    csv_tcp_content = "Date, {}-{}-{}\n\n".format(date[0:4], date[4:6], date[6:8])
    for hp in honeyports:
        csv_tcp_content += "{}, {}\n".format(hp.get_ip(), hp.get_log_folder())

        # Port - Hour Table
        csv_tcp_content += "\nPort-Hour Table\n"
        csv_tcp_content += "Port,,"
        for i in range(0, 24):
            csv_tcp_content += "{}H,".format(str(i))
        csv_tcp_content += "Daily\n"

        tcp_num_counter = hp.get_tcp_num_counter()
        tcp_size_counter = hp.get_tcp_size_counter()
        for port in TCP_Checking_Ports:
            num_row = "{},number,".format(str(port))
            size_row = ",size,"
            daily_num = 0
            daily_size = 0

            for hour in range(0, 24):
                key = "{}:{}".format(str(port), str(hour))
                num = tcp_num_counter[key]
                size = tcp_size_counter[key]
                daily_num += num
                daily_size += size
                num_row += "{},".format(str(num))
                if num != 0:
                    size_row += "{}B,".format(human_number(size, 1024))
                else:
                    size_row += "{},".format(human_number(size, 1024))

            num_row += "{}\n".format(str(daily_num))
            if daily_num != 0:
                size_row += "{}B\n".format(human_number(daily_size, 1024))
            else:
                size_row += "{}\n".format(human_number(daily_size, 1024))

            csv_tcp_content += num_row
            csv_tcp_content += size_row


        # Port - Country Table
        csv_tcp_content += "\nPort-Country Table\n"
        tcp_country_counter = hp.get_tcp_country_counter()
        countries = sorted(hp.get_tcp_countries())
        csv_tcp_content += "Port," + ",".join(countries) + "\n"
        for port in TCP_Checking_Ports:
            country_row = r"{},".format(str(port))
            for country in countries:
                key = r"{0}:{1}".format(str(port), country)
                country_row += "{},".format(str(tcp_country_counter[key]))
            country_row += "\n"
            csv_tcp_content += country_row

        # Source IPs
        csv_tcp_content += "Source IPs,Country-City,Access Ports\n"
        sorted_info = process_ip_country_port_info(hp.get_tcp_packets())
        sorted_info.sort(key=lambda x: x[Source_Country_Index])
        for entry in sorted_info:
            line = "{}, {}-{},".format(entry[Source_IP_Index], \
                   entry[Source_Country_Index], entry[Source_City_Index])
            for p in entry[Source_Ports_Index]:
                line += str(p) + "  "
            csv_tcp_content += line + "\n"

        csv_tcp_content += "\n\n"

    # Write to file
    report_dir = get_report_directory()
    csv_tcp_file = os.path.join(report_dir, CSV_Name_Format.format(date, "tcp"))
    with open(csv_tcp_file, "w+") as fp:
        fp.write(csv_tcp_content)


JSON_Pattern = \
"""{"index":{  "_index":"json_packets", "_type":"information" }}
{"src_ip":"%s", "dst_ip":"%s", "protocol":"%s", "packet_size":%d, "@timestamp":"%s", "country":"%s", "city":"%s", "src_port":%d, "dst_port":%d, "icmp_type":%d}
"""
JSON_DateTime_Format = "%m-%d-%Y:%H:%M:%S"

def generate_json_file(date, honeyports):
    json_content = ""

    for hp in honeyports:
        tcp_list = hp.get_tcp_packets()
        for tcp in tcp_list:
            json_entry = JSON_Pattern % (tcp.get_src_ip(), tcp.get_dst_ip(), "TCP", tcp.get_packet_size(),
                                             datetime.datetime.utcfromtimestamp(tcp.get_timestamp()).strftime(JSON_DateTime_Format),
                                             tcp.get_src_country(), tcp.get_src_city(), tcp.get_src_port(), tcp.get_dst_port(), -1)
            json_content += json_entry

        icmp_list = hp.get_icmp_packets()
        for icmp in icmp_list:
            json_entry = JSON_Pattern %(icmp.get_src_ip(), icmp.get_dst_ip(), "ICMP", icmp.get_packet_size(),
                                             datetime.datetime.utcfromtimestamp(icmp.get_timestamp()).strftime(JSON_DateTime_Format),
                                             icmp.get_src_country(), icmp.get_src_city(), -1, -1, icmp.get_icmp_type())
            json_content += json_entry

    # Save to file
    report_dir = get_report_directory()
    json_file = os.path.join(report_dir, JSON_Name_Format.format(date, "all"))
    with open(json_file, "w+") as fp:
        fp.write(json_content)


def main():
    #trytcp = TcpPacket("123.123", 1,"456.456", 3, 99, "CN", "Mian", 123456)
    #print trytcp.get_src_ip()
    #print "{'index':-1} {'src':'%s'} %d" % (trytcp.get_src_ip(), 123)
    #return

    # ---------- Preparation ----------
    # Check IP library before process datas
    ip_reader = geoip2.database.Reader(IP_Database_File)
    if not ip_reader:
        print "IP data cannot be found. Please check"
        return
    # Get input date
    date = get_input_date()
    # Sort ports
    TCP_Checking_Ports.sort()

    # ---------- Processing ----------
    # Create honeypot objects and process pcap files for each
    print "Processing ", date
    honeypot_list = []
    for hp_ip in AWS_honeypot_ips:
        hp = Honeypot(ip=hp_ip, name=Honeypot_IP_Name_Map[hp_ip], date=date)
        hp.process_pcaps()
        honeypot_list.append(hp)

    # ---------- Generating ----------
    # Generate the html, csv, json files
    generate_html_files(date, honeypot_list)
    generate_csv_files(date, honeypot_list)
    generate_json_file(date, honeypot_list)
    print "Finish Reports for ", date, "\n"
    return


if __name__ == '__main__':
    main()
