
import os


Parent_Folder = r"C:/Users/zhou.bin/Desktop/Honeypot"
Report_Folder = os.path.join(Parent_Folder, "Daily_Reports")
Script_Folder = os.path.join(Parent_Folder, "scripts/report_generator")
IP_Database_File = os.path.join(Script_Folder, "GeoLite2-City_20171107/GeoLite2-City.mmdb")


TCP_Checking_Ports = [502, 1911, 4911, 2222, 44818, 47808, 19999,
                      20000, 102, 2404, 8333]
ICMP_Checking_Types = [8]


Threshold_Tcp_Num = 100
Threshold_Tcp_Average_Size = 100
Country_Name_Replacement = {"Vietnam": "Viet Nam",
                            "Republic of Korea": "Korea, Republic of",
                            "Russia": "Russian Federation",
                            "Iran": "Iran, Islamic Republic of",
                            "Macedonia": "Macedonia, Republic of",
                            "U.S. Virgin Islands": "Virgin Islands, U.S.",
                            "Myanmar [Burma]": "Myanmar"}

Honeypot_IP_Name_Map = {"172.31.1.17": "ADSC_0",
                        "172.31.27.32": "ADSC_1",
                        "172.31.13.26": "ADSC_2",
                        "172.31.42.31": "ADSC_3",
                        "172.31.20.47": "ADSC_4"}

AWS_Honeypot_IPs = ["172.31.1.17", "172.31.27.32", "172.31.13.26",
                    "172.31.42.31", "172.31.20.47"]

# Formats in packets
JSON_DateTime_Format = "%m-%d-%Y:%H:%M:%S"


# Json log file entry pattern
JSON_Pattern = \
u"""{"index":{  "_index":"json_packets2", "_type":"information" }}
{"@timestamp":"%s", "year":%d, "month":%d, "day":%d, "hour":%d, "minute":%d, "second":%d,\
 "network_prtcl":"%s", "transport_prtcl":"%s", "application_prtcl":"%s",\
 "src_ip":"%s", "dst_ip":"%s", "src_port":%d, "dst_port":%d, "icmp_type":%d,\
 "packet_size":%d,  "country":"%s", "city":"%s", "country_code":"%s"}
"""

# Command to convert files from pcap to csv for protocol information
Wireshark_File = r"C:\Program Files\Wireshark\tshark.exe"
Pcap_Csv_Command = {
    "wireshark": r"C:\Program Files\Wireshark\tshark.exe",
    "options": ["-T", "fields", "-e", "frame.number", "-e", "_ws.col.Protocol", "-E", "header=y", "-E",
                "separator=,", "-E", "quote=d", "-E", "occurrence=f"],
}
Pcap_Csv_Command_String = \
""" "{}" -r "{}" -T fields -e frame.number -e _ws.col.Protocol -E header=y -E separator=, \
-E quote=d -E occurrence=f > "{}" """
