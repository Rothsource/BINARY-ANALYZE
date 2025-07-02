import re
from typing import List

pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', re.IGNORECASE)

def extract_emails(strings: List[str]) -> None:
    emails = sorted(set(email for s in strings for email in pattern.findall(s)))
    if not emails:
        print("Email Not Found.")
    else:
        for email in emails:
            print(email)
