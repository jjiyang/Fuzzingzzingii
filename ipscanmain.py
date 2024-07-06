from ip_scanner import IPSCANNER

ipscanner = IPSCANNER()

url = input('URL : ')
ip = input('IP : ')

ipscanner.execute_ip_scan(url, ip, 0, 255)


