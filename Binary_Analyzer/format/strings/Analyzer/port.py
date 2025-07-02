import re

pattern = re.compile(r':([0-9]{1,5})\b')

def extract_ports(strings):
    ports = set()

    for s in strings:
        for port in pattern.findall(s):
            port_num = int(port)
            if 1 <= port_num <= 65535:
                ports.add(port_num)

    if not ports:
        print("Not Found Ports")
    else:
        print("Found Ports:")
        for port in sorted(ports):
            print(port)

