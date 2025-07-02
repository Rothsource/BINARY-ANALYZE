import re

pattern = re.compile(r'HKEY_[A-Z_]+\\[^\\]+(?:\\[^\\]+)*', re.IGNORECASE)

def extract_registry_keys(strings):
    keys = sorted(set(match for s in strings for match in pattern.findall(s)))
    if not keys:
        print("Not Found Keys")
    else:
        for key in keys:
            print(key)
