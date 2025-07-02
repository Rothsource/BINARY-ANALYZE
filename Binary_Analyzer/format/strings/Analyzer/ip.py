import re

pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

def extract_ips(strings):
    ips = sorted(set(match for s in strings for match in pattern.findall(s)))
    if not ips:
        print("IPs Not Found")
    else:
        for ip in ips:
            print(ip)
