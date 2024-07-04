import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlunparse


class PORTSCANNER:
    def __init__(self):
        self.ipv4 = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.ipv6 = re.compile(r'\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b|\b(?:[A-F0-9]{1,4}:){1,7}:(?:[A-F0-9]{1,4})?\b|\b(?:[A-F0-9]{1,4}:){1,6}:(?:[A-F0-9]{1,4}:)?(?:[A-F0-9]{1,4})?\b|\b(?:[A-F0-9]{1,4}:){1,5}:(?:[A-F0-9]{1,4}:){1,2}(?:[A-F0-9]{1,4})?\b|\b(?:[A-F0-9]{1,4}:){1,4}:(?:[A-F0-9]{1,4}:){1,3}(?:[A-F0-9]{1,4})?\b|\b(?:[A-F0-9]{1,4}:){1,3}:(?:[A-F0-9]{1,4}:){1,4}(?:[A-F0-9]{1,4})?\b|\b(?:[A-F0-9]{1,4}:){1,2}:(?:[A-F0-9]{1,4}:){1,5}(?:[A-F0-9]{1,4})?\b|\b[A-F0-9]{1,4}:(?::(?:[A-F0-9]{1,4}:){0,5}[A-F0-9]{1,4})?\b|\b:(?::(?:[A-F0-9]{1,4}:){0,6}[A-F0-9]{1,4})?\b')
        with open('./payloads/SSRF/port.txt', 'r') as f:
            self.port_num = [port.strip() for port in f]

    def file_close(self):
        self.port_num.close()

    def requesting(self, url):
        if requests.get(url, timeout=2).status_code == 200:
            print(f'Port Scanner :\t{url} open!!')
        else:
            print(f'Port Scanner :\t{url} close!!')

    def ip_match(self, url, param):
        checking = url + param

        if re.search(self.ipv4, checking):
            return url, param
        elif re.search(self.ipv6, checking):
            return url, param
        else:
            return False

    def port_scan(self, url, param):
        url_list = []
        for port in self.port_num:
            parsed_param = urlparse(param)
            domain = parsed_param.netloc
            domain = domain.replace(f':{parsed_param.port}','') if parsed_param.port else domain

            if domain != "":
                param_domain = domain + f':{port}'
                port_param = parsed_param._replace(netloc=param_domain)
                port_param = urlunparse(port_param)
                port_url = url+port_param
                url_list.append(port_url)

        with ThreadPoolExecutor(max_workers=5) as executor:
            list(executor.map(self.requesting, url_list))
