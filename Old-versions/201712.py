#!/usr/bin/env python

# This is the old version of generating daily reports for AWS honeypot data
# Please refer to the latest version for more details.


import os, sys
import datetime
from sets import Set
from collections import Counter

from pcapng import FileScanner
from pcapng.blocks import EnhancedPacket

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

import geoip2.database


Map_Folder_IP = {"172.31.1.17": "ADSC_0",
                 "172.31.27.32": "ADSC_1",
                 "172.31.13.26": "ADSC_2",
                 "172.31.42.31": "ADSC_3",
                 "172.31.20.47": "ADSC_4"}
Folder_names = ["ADSC_0", "ADSC_1", "ADSC_2", "ADSC_3", "ADSC_4"]
AWS_honeypot_ips = ["172.31.1.17", "172.31.27.32", "172.31.13.26",
                     "172.31.42.31", "172.31.20.47"]
AWS_honeypot_ports = [502, 1911, 4911, 2222, 44818, 47808, 19999,
                       20000, 102, 2404, 8333, 8332]
Report_Directory_Name = "Daily_Reports"
IP_Database_File = "GeoLite2-City_20171107/GeoLite2-City.mmdb"


Source_IP_Index = 0
Source_Country_Index = 1
Source_City_Index = 2
Source_Ports_Index = 3


class Honeypot():
    def __init__(self, ip):
        AWS_honeypot_ports.sort()
        self.ip = ip
        self.folder_name = Map_Folder_IP[ip]
        self.logs = []
        self.num_counter = Counter()    # key is "port:hour"
        self.size_counter = Counter()   # key is "port:hour"
        self.country_counter = Counter()  # key is "port:country"
        self.countries = Set([])
        self.source_ip = []  # entry = [ip, country, city, [ports]]
        

    def setLogFiles(self, files):
        for file in files:
            if self.folder_name in file:
                self.logs.append(file)


    def process(self):
        for logfile in self.logs:
            # Get hour info from file name
            # File format is: yyyymmdd-hh.pcap
            print "Procssing: ", logfile
            hour = (logfile.split('.')[-2]).split('-')[-1]

            fp = open(logfile, "rb")
            scan_result = FileScanner(fp)

            for block in scan_result:
                if not isinstance(block, EnhancedPacket):
                    continue

                assert block.interface.link_type == 1  # must be ethernet!

                decoded = Ether(block.packet_data)

                _pl1 = decoded.payload
                if isinstance(_pl1, IP):
                    if _pl1.dst == self.ip:
                        _pl2 = _pl1.payload
                        if hasattr(_pl2, "dport"):
                            port = _pl2.dport
                            if port in AWS_honeypot_ports:
                                hour = hour.lstrip('0')
                                if hour == "":
                                    hour = "0"
                                key = str(port) + ":" + hour
                                self.num_counter[key] += 1
                                self.size_counter[key] += block.packet_len
                                self.updateSourceIpPort(_pl1.src, port)
                                #self.source_ip.add(_pl1.src)

            fp.close()


    def updateSourceIpPort(self, ip, port):
        for index, entry in enumerate(self.source_ip):
            if entry[Source_IP_Index] == ip:
                key = str(port) + ":" + entry[Source_Country_Index]
                self.country_counter[key] += 1

                for p in entry[Source_Ports_Index]:
                    if p == port:
                        return
                self.source_ip[index][Source_Ports_Index].append(port)
                return

        country, city = getIPDetails(ip)
        self.countries.add(country)
        self.source_ip.append([ip, country, city.encode('utf-8'), [port]])
        key = str(port) + ":" + country
        self.country_counter[key] += 1



    def getIP(self):
        return self.ip

    def getLogFolderName(self):
        return self.folder_name

    def getNumCounter(self):
        return self.num_counter

    def getSizeCounter(self):
        return self.size_counter

    def getCountryCounter(self):
        return self.country_counter

    def getCountries(self):
        return self.countries

    def getSourceIP(self):
        return self.source_ip

    def printObject(self):
        print "IP: ", self.ip
        print "Folder: ", self.folder_name
        print "Logs: ", self.logs
        print "Num_counter: ", self.num_counter
        print "Size_counter: ", self.size_counter
        print "Source ip: ", self.source_ip
        print "Countries: ", self.countries



def human_number(num, k=1000):
    powers = [''] + list('kMGTPEY')
    assert isinstance(num, (int, long))
    for i, suffix in enumerate(powers):
        if (num < (k ** (i + 1))) or (i == len(powers) - 1):
            return '{0:d}{1}'.format(int(round(num / (k ** i))), suffix)
    raise AssertionError('Should never reach this')


def getInputDate():
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


def getFilesOfDate(date):
    files = []
    parent_dir = os.path.dirname(os.getcwd())
    for folder_name in Folder_names:
        log_folder = os.path.join(parent_dir, folder_name)
        if not os.path.isdir(log_folder):
            print "The folder "+folder_name+" is missing is current directory."
            continue
        log_files = os.listdir(log_folder)
        for log_file in log_files:
            if date in log_file:
                files.append(os.path.join(log_folder, log_file))

    return files


def getIPDetails(ip):
    IPreader = geoip2.database.Reader(IP_Database_File)
    try:
        response = IPreader.city(ip)
        if response.country.name and response.city.name:
            return response.country.name, response.city.name
        elif response.country.name and not response.city.name:
            return response.country.name, "None"
        elif not response.country.name and response.city.name:
            return "None", response.city.name
        else:
            return "None", "None"
    except:
        return "None", "None"


def getReportDirectory():
    parent_dir = os.path.dirname(os.getcwd())
    report_dir = os.path.join(parent_dir, Report_Directory_Name)
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
    return report_dir


def generateReportHTML(date, honeypots):
    print "GEnerating HTML"
    report_dir = getReportDirectory()
    fp = open(report_dir+"/"+date+"-report.html", "w+")

    html=["<html>"]
    title = r"<header><h2>Date: {}-{}-{}</h2></header><br/>".\
            format(date[0:4], date[4:6], date[6:8])
    html.append(title)

    num_row = ""
    size_row = ""
    for hp in honeypots:
        hp_header = r"<header><h3>{}:  {}</h3></header>".\
                    format(hp.getIP(), hp.getLogFolderName())
        html.append(hp_header)


        # Table for port-hour
        html.append(r"<body><p>Port-Hour Table</p><table border='1'>")
        column_header = r"<tr><td>Port</td><td></td>"
        for i in range(0, 24):
            column_header += r"<td width=50>{}H</td>".format(str(i))
        column_header += r"<td>Daily</td></tr>"
        html.append(column_header)
    
        num_counter = hp.getNumCounter()
        size_counter = hp.getSizeCounter()
        for port in AWS_honeypot_ports:
            num_row = r"<tr><td>{}</td><td>number</td>".format(str(port))
            size_row = r"<tr><td></td><td>size</td>"
            daily_num = 0
            daily_size = 0
            for hour in range(0, 24):
                key = r"{0}:{1}".format(str(port), str(hour))
                num = num_counter[key]
                size = size_counter[key]
                daily_num += num
                daily_size += size
                if num != 0:
                    num_row += r"<td width=50 bgcolor='#F4B942'>{}</td>".\
                                format(str(num))
                    size_row += r"<td width=50 bgcolor='#F4B942'>{}B</td>".\
                                format(human_number(size, 1024))
                else:
                    num_row += r"<td width=50>{}</td>".format(str(num))
                    size_row += r"<td width=50>{}</td>".format(human_number(size, 1024))
            
            if daily_num != 0:
                num_row += r"<td width=50 bgcolor='#F4B942'>{}</td></tr>".\
                            format(str(daily_num))
                size_row += r"<td width=50 bgcolor='#F4B942'>{}B</td></tr>".\
                            format(human_number(daily_size, 1024))
            else:
                num_row += r"<td width=50>{}</td></tr>".format(str(daily_num))
                size_row += r"<td width=50>{}</td></tr>".format(human_number(daily_size, 1024))

            html.append(num_row)
            html.append(size_row)
        html.append(r"</table></body>")


        # Table for port-country
        html.append(r"<br/><p>Port-Country Table</p><body><table border='1'>")
        country_counter = hp.getCountryCounter()
        countries = sorted(hp.getCountries())
        html.append(r"<tr><td>Port</td><td>{}</td></tr>".format(r"</td><td>".join(countries)))
        for port in AWS_honeypot_ports:
            country_row = r"<tr><td>{}</td>".format(str(port))
            for country in countries:
                key = r"{0}:{1}".format(str(port), country)
                country_num = country_counter[key]
                if country_num != 0:
                    country_row += r"<td width=50 bgcolor='#F4B942'>{}</td>".\
                                    format(str(country_num))
                else:
                    country_row += r"<td width=50>{}</td>".format(str(country_num))
            country_row += r"</tr>"
            html.append(country_row)
        html.append(r"</table></body>")


        html.append(r"<p>Source IPs: </p>")
        sorted_ips = hp.getSourceIP()
        sorted_ips.sort(key=lambda x: x[Source_Country_Index])
        for entry in sorted_ips:
            line = "{} - {}, {} - Access port: ".format(entry[Source_IP_Index],\
                entry[Source_Country_Index], entry[Source_City_Index])
            for p in entry[Source_Ports_Index]:
                line += str(p) + "  "
            html.append(r"<p>{}</p>".format(line))

        html.append(r"<br/>")

    html.append("</html>")
    fp.write(''.join(html))

    fp.close()


def generateReportCSV(date, honeypots):
    print "Generating CSV."
    report_dir = getReportDirectory()
    fp = open(report_dir+"/"+date+"-report.csv", "w+")

    fp.write("Date, {}-{}-{}\n\n".format(date[0:4], date[4:6], date[6:8]))
    for hp in honeypots:
        fp.write("{}, {}\n".format(hp.getIP(), hp.getLogFolderName()))

        # Port - Hour Table
        column_header = "Port,,"
        for i in range(0, 24):
            column_header += "{}H,".format(str(i))
        column_header += "Daily\n" 
        fp.write(column_header)

        num_counter = hp.getNumCounter()
        size_counter = hp.getSizeCounter()
        for port in AWS_honeypot_ports:
            num_row = "{},number,".format(str(port))
            size_row = ",size,"
            daily_num = 0
            daily_size = 0

            for hour in range(0, 24):
                key = "{0}:{1}".format(str(port), str(hour))
                num = num_counter[key]
                size = size_counter[key]
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

            fp.write(num_row)
            fp.write(size_row)


        # Table for port-country
        fp.write("\nPort-Country Table\n")
        country_counter = hp.getCountryCounter()
        countries = sorted(hp.getCountries())
        fp.write("Port," + ",".join(countries) + "\n")
        for port in AWS_honeypot_ports:
            country_row = r"{},".format(str(port))
            for country in countries:
                key = r"{0}:{1}".format(str(port), country)
                country_row += "{},".format(str(country_counter[key]))
            country_row += "\n"
            fp.write(country_row)


        # Source IPs
        fp.write("Source IPs,Country-City,Access Ports\n")
        sorted_ips = hp.getSourceIP()
        sorted_ips.sort(key=lambda x: x[Source_Country_Index])
        for entry in sorted_ips:
            line = "{}, {}-{},".format(entry[Source_IP_Index],\
                   entry[Source_Country_Index], entry[Source_City_Index])
            for p in entry[Source_Ports_Index]:
                line += str(p) + "  "
            fp.write(line+"\n")

        fp.write("\n\n")

    fp.close()



def main():

    # Preparation: Get input date and log files, ip database
    date = getInputDate()
    files = getFilesOfDate(date)
    if files == []:
        print "No log files found. Please check"
        return
    # Check before process datas
    IPreader = geoip2.database.Reader('GeoLite2-City_20171107/GeoLite2-City.mmdb')


    # Generate data from log files
    print "Processing ", date
    honeypots = []
    for ip in AWS_honeypot_ips:
        print ip
        hp = Honeypot(ip)
        hp.setLogFiles(files)
        hp.process()

        #hp.printObject()
        honeypots.append(hp)


    # Print out for report
    generateReportHTML(date, honeypots)
    generateReportCSV(date, honeypots)
    print "Finish Reports for ", date, "\n"



if __name__ == '__main__':
    main()

