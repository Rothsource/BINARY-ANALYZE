import re

domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

def extract_domains(strings):
    domains = set()

    for s in strings:
        for domain in domain_pattern.findall(s):
            if not ip_pattern.match(domain) and domain != 'localhost':
                domains.add(domain)

    if not domains:
        print("Domain Not Found")
    else:
        print("Found domains:")
        for domain in sorted(domains):
            print(domain)
