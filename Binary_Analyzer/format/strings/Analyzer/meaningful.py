import re

pattern = re.compile(r'[A-Z][^.!?]*[.!?]')

def extract_meaningful_sentences(strings):
    sentences = set()

    for s in strings:
        for sentence in pattern.findall(s):
            words = sentence.split()
            if 3 <= len(words) <= 20 and 10 <= len(sentence) <= 200:
                sentences.add(sentence.strip())

    if not sentences:
        print("Not found any meaningful sentence")
    else:
        print("Found sentences:")
        for sentence in sorted(sentences):
            print(sentence)

