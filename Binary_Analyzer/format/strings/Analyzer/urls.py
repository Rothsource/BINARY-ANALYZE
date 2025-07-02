import re

pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)

def extract_urls(strings):
    urls = sorted(set(match for s in strings for match in pattern.findall(s)))
    if not urls:
        print("URL Not Found")
    else:
        for url in urls:
            print(url)
