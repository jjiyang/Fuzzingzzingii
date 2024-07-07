import requests
from concurrent.futures import ThreadPoolExecutor
import re


class IPSCANNER:
    def __init__(self):
        self.ip_band_a = re.compile(r'10\.(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5]|x)\.(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5]|x)\.(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5]|x)')
        self.ip_band_b = re.compile(r'172\.(?:1[6-9]|2[0-9]|3[0-1]|x)\.(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5]|x)\.(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5]|x)')
        self.ip_band_c = re.compile(r'192\.168\.(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5]|x)\.(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5]|x)')

    def requesting(self, scan_list):
        for url in scan_list:
            resp = requests.get(url)
            print(f'IP\t: {url}\t\tSTATUS CODE\t: {resp.status_code}')

    def customizing(self, url, ip, lower, upper):
        scan_list = []
        if self.error_handler(ip, lower, upper):
            for num in range(lower, upper+1, 1):
                target_num = str(num)
                target_ip = ip.replace('x', target_num)
                target_url = url + target_ip
                scan_list.append(target_url)

        return scan_list

    def error_handler(self, ip, lower, upper):
        if not re.search(self.ip_band_a, ip) or not re.search(self.ip_band_b, ip) or not re.search(self.ip_band_c, ip):
            print(f"URL Error\t\t Usage example : 192.168.0.x")
            return False

        if lower < 0:
            print(f"IP lower bound Error\t\t Should be 0 ~ 255")
            return False

        if upper > 255:
            print(f"IP upper bound Error\t\t Should be 0 ~ 255")
            return False

    def execute_ip_scan(self, url, ip, lower, upper):
        scan_list = self.customizing(url, ip, lower, upper)

        with ThreadPoolExecutor(max_workers=5) as executor:
            list(executor.map(self.requesting, scan_list))
