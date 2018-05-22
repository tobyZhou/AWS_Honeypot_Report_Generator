
import pycountry
import subprocess

# Local modules
import config
import geoip2.database


# Found out the country and city information based in ip address
def get_ip_country_city(ip):
    if not ip:
        return "None", "None"

    ip_reader = geoip2.database.Reader(config.IP_Database_File)
    try:
        response = ip_reader.city(ip)
        if response.country.name:
            country = response.country.name.encode('utf-8')
            if country in config.Country_Name_Replacement:
                country = config.Country_Name_Replacement[country]
        else:
            country = "None"

        if response.city.name:
            city = response.city.name.encode('utf-8')
        else:
            city = "None"

        return country, city
    except:
        return "None", "None"


# Helper functions for generating html, csv, json files
def human_number(num, k=1000):
    powers = [''] + list('kMGTPEY')
    assert isinstance(num, (int, long))
    for i, suffix in enumerate(powers):
        if (num < (k ** (i + 1))) or (i == len(powers) - 1):
            return '{0:d}{1}'.format(int(round(num / (k ** i))), suffix)
    raise AssertionError('Should never reach this')


def get_abbreviation(country):
    return pycountry.countries.get(name=country).alpha_2


def load_protocols(csv_file):
    with open(csv_file, 'r') as f:
        protocol_list = []
        for line in f.readlines():
            id_value = line.strip().replace('"', '').split(',')
            if not id_value[0].isdigit():
                continue
            else:
                protocol_list.append(id_value[1])
    return protocol_list


def convert_pcap_to_csv(pcap_file, csv_file):
    cmd = [config.Pcap_Csv_Command['wireshark'], "-r", pcap_file]
    cmd.extend(config.Pcap_Csv_Command['options'])
    cmd.append(">")
    cmd.append(csv_file)
    print subprocess.check_output(cmd)
