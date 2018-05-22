#!/usr/bin/env python

"""
    This script is for AWS data
    1. only consider TCP and ICMP
"""

# Modules/Libs
import os
import sys
import datetime
import geoip2.database

# Local modules
import config
import utility
from honeypot import Honeypot


HTML_Name_Format = "{}-{}.html"  # date-type. Eg: 20171201-tcp.html
CSV_Name_Format = "{}-{}.csv"
JSON_Name_Format = "{}-{}.json"

Source_IP_Index = 0
Source_Country_Index = 1
Source_City_Index = 2
Source_Ports_Index = 3

Yellow_Color = "#F4B942"
Orange_Color = "#E84629"


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


def generate_html_files(date, honeypots, tcp_check_ports):
    print "Generating htmls"
    generate_html_tcp_file(date, honeypots, tcp_check_ports)
    generate_html_icmp_file(date, honeypots)


def generate_html_tcp_file(date, honeypots, tcp_check_ports):
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
        for port in tcp_check_ports:
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
                                format(Yellow_Color, utility.human_number(size, 1024))
                else:
                    num_row += r"<td width=50>{}</td>".format(str(num))
                    size_row += r"<td width=50>{}</td>".format(utility.human_number(size, 1024))

            if daily_num != 0:
                if daily_num > config.Threshold_Tcp_Num:
                    bg_color = Orange_Color
                else:
                    bg_color = Yellow_Color
                num_row += r"<td width=50 bgcolor='{}'>{}</td><td>-</td></tr>".format(bg_color, str(daily_num))

                if int(daily_size/daily_num) > config.Threshold_Tcp_Average_Size:
                    bg_color = Orange_Color
                else:
                    bg_color = Yellow_Color
                size_row += r"<td width=50 bgcolor='{}'>{}B</td><td bgcolor='{}'>{}B</td></tr>".\
                            format(Yellow_Color, utility.human_number(daily_size, 1024), bg_color, daily_size/daily_num)
            else:
                num_row += r"<td width=50>{}</td><td>-</td></tr>".format(str(daily_num))
                size_row += r"<td width=50>{}</td><td>0</td></tr>".format(utility.human_number(daily_size, 1024))

            html_tcp_content += num_row
            html_tcp_content += size_row
        html_tcp_content += r"</table></body>"

        # Table for port-country
        html_tcp_content += r"<br/><p>Port-Country Table</p><body><table border='1'>"
        country_counter = hp.get_tcp_country_counter()
        countries = sorted(hp.get_tcp_countries())
        html_tcp_content += r"<tr><td>Port</td><td>{}</td></tr>".format(r"</td><td>".join(countries))
        for port in tcp_check_ports:
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
            line = "{} - {}, {} - Access port: ".format(entry[Source_IP_Index],
                                                        entry[Source_Country_Index],
                                                        entry[Source_City_Index])
            for p in entry[Source_Ports_Index]:
                line += str(p) + "  "
            html_tcp_content += r"<p>{}</p>".format(line)

        html_tcp_content += r"<br/>"
    html_tcp_content += "</html>"

    # Write to file
    html_tcp_file = os.path.join(config.Report_Folder, HTML_Name_Format.format(date, "tcp"))
    with open(html_tcp_file, "w+") as fp:
        fp.write(html_tcp_content)


def generate_html_icmp_file(date, honeypots):
    html_icmp_content = "<html>"
    html_icmp_content += r"<header><h2>Date: {}-{}-{}</h2></header><br/>". \
                         format(date[0:4], date[4:6], date[6:8])
    for hp in honeypots:
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
        for ctype in config.ICMP_Checking_Types:
            daily_num = 0
            daily_size = 0
            num_row = r"<tr><td>{}</td><td>number</td>".format(str(ctype))
            size_row = r"<tr><td></td><td>size</td>"

            for hour in range(0, 24):
                key = r"{}:{}".format(str(ctype), str(hour))
                num = icmp_num_counter[key]
                size = icmp_size_counter[key]
                daily_num += num
                daily_size += size
                if num != 0:
                    num_row += r"<td width=50 bgcolor='#F4B942'>{}</td>". \
                        format(str(num))
                    size_row += r"<td width=50 bgcolor='#F4B942'>{}B</td>". \
                        format(utility.human_number(size, 1024))
                else:
                    num_row += r"<td width=50>{}</td>".format(str(num))
                    size_row += r"<td width=50>{}</td>".format(utility.human_number(size, 1024))

            if daily_num != 0:
                num_row += r"<td width=50 bgcolor='#F4B942'>{}</td></tr>". \
                    format(str(daily_num))
                size_row += r"<td width=50 bgcolor='#F4B942'>{}B</td></tr>". \
                    format(utility.human_number(daily_size, 1024))
            else:
                num_row += r"<td width=50>{}</td></tr>".format(str(daily_num))
                size_row += r"<td width=50>{}</td></tr>".format(utility.human_number(daily_size, 1024))

            html_icmp_content += num_row
            html_icmp_content += size_row
        html_icmp_content += r"</table></body>"

        # Table for icmp type - country
        html_icmp_content += r"<br/><p>Icmp Type-Country Table</p><body><table border='1'>"
        country_counter = hp.get_icmp_country_counter()
        countries = sorted(hp.get_icmp_countries())
        html_icmp_content += r"<tr><td>Type</td><td>{}</td></tr>".format(r"</td><td>".join(countries))
        for ctype in config.ICMP_Checking_Types:
            country_row = r"<tr><td>{}</td>".format(str(ctype))
            for country in countries:
                key = r"{}:{}".format(str(ctype), country)
                country_num = country_counter[key]
                if country_num != 0:
                    country_row += r"<td width=50 bgcolor='#F4B942'>{}</td>".format(str(country_num))
                else:
                    country_row += r"<td width=50>{}</td>".format(str(country_num))
            country_row += r"</tr>"
            html_icmp_content += country_row
        html_icmp_content += r"</table></body>"

        html_icmp_content += r"<p>Source IPs: </p>"
        sorted_info = process_icmp_ip_info(hp.get_icmp_packets())
        sorted_info.sort(key=lambda x: x[Source_Country_Index])
        for entry in sorted_info:
            line = "{} - {}, {}".format(entry[Source_IP_Index], entry[Source_Country_Index], entry[Source_City_Index])
            html_icmp_content += r"<p>{}</p>".format(line)

        html_icmp_content += r"<br/><br/>"

    html_icmp_content += "</html>"

    # Write to file
    html_icmp_file = os.path.join(config.Report_Folder, HTML_Name_Format.format(date, "icmp"))
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
    for packet in packet_list:  # tcp packets only
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


def generate_csv_files(date, honeypots, tcp_check_ports):
    print "Generating CSVs"
    generate_csv_tcp_file(date, honeypots, tcp_check_ports)
    generate_csv_icmp_file(date, honeypots)


def generate_csv_icmp_file(date, honeypots):
    csv_icmp_content = "Date, {}-{}-{}\n\n".format(date[0:4], date[4:6], date[6:8])
    for hp in honeypots:
        csv_icmp_content += "{}, {}\n".format(hp.get_ip(), hp.get_log_folder())

        # Type - Hour Table
        csv_icmp_content += "\nICMP Type-Hour Table\n"
        csv_icmp_content += "Type,,"
        for i in range(0, 24):
            csv_icmp_content += "{}H,".format(str(i))
        csv_icmp_content += "Daily\n"

        icmp_num_counter = hp.get_icmp_num_counter()
        icmp_size_counter = hp.get_icmp_size_counter()
        for ctype in config.ICMP_Checking_Types:
            num_row = "{},number,".format(str(ctype))
            size_row = ",size,"
            daily_num = 0
            daily_size = 0

            for hour in range(0, 24):
                key = "{}:{}".format(str(ctype), str(hour))
                num = icmp_num_counter[key]
                size = icmp_size_counter[key]
                daily_num += num
                daily_size += size
                num_row += "{},".format(str(num))
                if num != 0:
                    size_row += "{}B,".format(utility.human_number(size, 1024))
                else:
                    size_row += "{},".format(utility.human_number(size, 1024))

            num_row += "{}\n".format(str(daily_num))
            if daily_num != 0:
                size_row += "{}B\n".format(utility.human_number(daily_size, 1024))
            else:
                size_row += "{}\n".format(utility.human_number(daily_size, 1024))

            csv_icmp_content += num_row
            csv_icmp_content += size_row

        # Type - Country Table
        csv_icmp_content += "\nICMP Type-Country Table\n"
        icmp_country_counter = hp.get_icmp_country_counter()
        countries = sorted(hp.get_icmp_countries())
        csv_icmp_content += "Type," + ",".join(countries) + "\n"
        for ctype in config.ICMP_Checking_Types:
            country_row = r"{},".format(str(ctype))
            for country in countries:
                key = r"{}:{}".format(str(ctype), country)
                country_row += "{},".format(str(icmp_country_counter[key]))
            country_row += "\n"
            csv_icmp_content += country_row

        # Source IPs
        csv_icmp_content += "Source IPs,Country-City\n"
        sorted_info = process_icmp_ip_info(hp.get_icmp_packets())
        sorted_info.sort(key=lambda x: x[Source_Country_Index])
        for entry in sorted_info:
            line = "{}, {}-{},".format(entry[Source_IP_Index],
                                       entry[Source_Country_Index],
                                       entry[Source_City_Index])
            csv_icmp_content += line + "\n"

        csv_icmp_content += "\n\n"

    # Write to file
    csv_icmp_file = os.path.join(config.Report_Folder, CSV_Name_Format.format(date, "icmp"))
    with open(csv_icmp_file, "w+") as fp:
        fp.write(csv_icmp_content)


def generate_csv_tcp_file(date, honeypots, tcp_check_ports):
    csv_tcp_content = "Date, {}-{}-{}\n\n".format(date[0:4], date[4:6], date[6:8])
    for hp in honeypots:
        csv_tcp_content += "{}, {}\n".format(hp.get_ip(), hp.get_log_folder())

        # Port - Hour Table
        csv_tcp_content += "\nPort-Hour Table\n"
        csv_tcp_content += "Port,,"
        for i in range(0, 24):
            csv_tcp_content += "{}H,".format(str(i))
        csv_tcp_content += "Daily\n"

        tcp_num_counter = hp.get_tcp_num_counter()
        tcp_size_counter = hp.get_tcp_size_counter()
        for port in tcp_check_ports:
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
                    size_row += "{}B,".format(utility.human_number(size, 1024))
                else:
                    size_row += "{},".format(utility.human_number(size, 1024))

            num_row += "{}\n".format(str(daily_num))
            if daily_num != 0:
                size_row += "{}B\n".format(utility.human_number(daily_size, 1024))
            else:
                size_row += "{}\n".format(utility.human_number(daily_size, 1024))

            csv_tcp_content += num_row
            csv_tcp_content += size_row

        # Port - Country Table
        csv_tcp_content += "\nPort-Country Table\n"
        tcp_country_counter = hp.get_tcp_country_counter()
        countries = sorted(hp.get_tcp_countries())
        csv_tcp_content += "Port," + ",".join(countries) + "\n"
        for port in tcp_check_ports:
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
            line = "{}, {}-{},".format(entry[Source_IP_Index], entry[Source_Country_Index], entry[Source_City_Index])
            for p in entry[Source_Ports_Index]:
                line += str(p) + "  "
            csv_tcp_content += line + "\n"

        csv_tcp_content += "\n\n"

    # Write to file
    csv_tcp_file = os.path.join(config.Report_Folder, CSV_Name_Format.format(date, "tcp"))
    with open(csv_tcp_file, "w+") as fp:
        fp.write(csv_tcp_content)


def generate_json_file(date, honeypots):
    json_content = ""

    for hp in honeypots:
        tcp_list = hp.get_tcp_packets()
        for tcp in tcp_list:
            json_entry = config.JSON_Pattern % (tcp.get_datetime(), tcp.get_year(), tcp.get_month(), tcp.get_day(),
                                                tcp.get_hour(), tcp.get_minute(), tcp.get_second(),
                                                tcp.get_network_prtcl(), tcp.get_transport_prtcl(),
                                                tcp.get_application_prtcl(), tcp.get_src_ip(), tcp.get_dst_ip(),
                                                tcp.get_src_port(), tcp.get_dst_port(), -1,
                                                int(tcp.get_packet_size()), tcp.get_src_country(), tcp.get_src_city(),
                                                tcp.get_src_country_code_2l())
            json_content += json_entry

        icmp_list = hp.get_icmp_packets()
        for icmp in icmp_list:
            json_entry = config.JSON_Pattern % (icmp.get_datetime(), icmp.get_year(), icmp.get_month(), icmp.get_day(),
                                                icmp.get_hour(), icmp.get_minute(), icmp.get_second(),
                                                icmp.get_network_prtcl(), icmp.get_transport_prtcl(),
                                                icmp.get_application_prtcl(), icmp.get_src_ip(), icmp.get_dst_ip(),
                                                -1, -1, icmp.get_icmp_type(),
                                                icmp.get_packet_size(), icmp.get_src_country(), icmp.get_src_city(),
                                                icmp.get_src_country_code_2l())
            json_content += json_entry

    # Save to file
    json_file = os.path.join(config.Report_Folder, JSON_Name_Format.format(date, "all"))
    with open(json_file, "w+") as fp:
        fp.write(json_content.encode('utf-8'))


def main():
    #trytcp = TcpPacket("123.123", 1,"456.456", 3, 99, "CN", "Mian", 123456)
    #print trytcp.get_src_ip()
    #print "{'index':-1} {'src':'%s'} %d" % (trytcp.get_src_ip(), 123)
    #return

    # ---------- Preparation ----------
    # Check IP library before process datas
    ip_reader = geoip2.database.Reader(config.IP_Database_File)
    if not ip_reader:
        print "IP data cannot be found. Please check"
        return
    # Get input date
    date = get_input_date()
    # Sort ports
    tcp_check_ports = config.TCP_Checking_Ports[:]
    tcp_check_ports.sort()

    # ---------- Processing ----------
    # Create honeypot objects and process pcap files for each
    print "Processing ", date
    honeypot_list = []
    for hp_ip in config.AWS_Honeypot_IPs:
        hp = Honeypot(ip=hp_ip,
                      name=config.Honeypot_IP_Name_Map[hp_ip],
                      date=date)
        hp.process_pcaps()
        honeypot_list.append(hp)

    # ---------- Generating ----------
    # Generate the html, csv, json files
    generate_html_files(date, honeypot_list, tcp_check_ports)
    generate_csv_files(date, honeypot_list, tcp_check_ports)
    generate_json_file(date, honeypot_list)
    print "Finish Reports for ", date, "\n"
    return


if __name__ == '__main__':
    main()
