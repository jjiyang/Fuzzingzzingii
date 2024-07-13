from fuzzers.ssrf.ip_scanner import IPSCANNER


def ipscan():

    ipscanner = IPSCANNER()

    url = input('URL : ')
    ip = input('IP : ')
    lower = input('Lower band : ')
    upper = input('Upper band : ')

    ipscanner.execute_ipscan(url, ip, lower, upper)


