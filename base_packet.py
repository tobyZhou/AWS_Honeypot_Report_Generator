
import datetime

# Local modules
import utility
import config


class BasePacket:
    def __init__(self, src_ip="", dst_ip="", packet_size=0, country="", city="", timestamp=0,
                 network_prtcl="", transport_prtcl="", application_prtcl=""):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.packet_size = packet_size
        self.country = country
        self.city = city
        if not self.country:
            self.country, self.city = utility.get_ip_country_city(self.src_ip)
        self.country_code = utility.get_abbreviation(self.country)
        self.timestamp = timestamp

        self.application_prtcl = application_prtcl
        self.transport_prtcl = transport_prtcl
        self.network_prtcl = network_prtcl

    def get_src_ip(self):
        return self.src_ip

    def get_dst_ip(self):
        return self.dst_ip

    def get_packet_size(self):
        return self.packet_size

    def get_src_country(self):
        return self.country.decode('utf-8')

    def get_src_country_code_2l(self):
        return self.country_code

    def get_src_city(self):
        return self.city.decode('utf-8')

    def get_src_country_city(self):
        return self.get_src_country(), self.get_src_city()

    def get_application_prtcl(self):
        return self.application_prtcl

    def get_transport_prtcl(self):
        return self.transport_prtcl

    def get_network_prtcl(self):
        return self.network_prtcl

    def get_timestamp(self):
        return self.timestamp

    def get_datetime(self):
        return datetime.datetime.utcfromtimestamp(self.timestamp).strftime(config.JSON_DateTime_Format)

    def get_year(self):
        return int(datetime.datetime.utcfromtimestamp(self.timestamp).strftime("%Y"))

    def get_month(self):
        return int(datetime.datetime.utcfromtimestamp(self.timestamp).strftime("%m"))

    def get_day(self):
        return int(datetime.datetime.utcfromtimestamp(self.timestamp).strftime("%d"))

    def get_hour(self):
        return int(datetime.datetime.utcfromtimestamp(self.timestamp).strftime("%H"))

    def get_minute(self):
        return int(datetime.datetime.utcfromtimestamp(self.timestamp).strftime("%M"))

    def get_second(self):
        return int(datetime.datetime.utcfromtimestamp(self.timestamp).strftime("%S"))
