from .extract_strings import extractstrings 
def all(file_path):
    strings = extractstrings(file_path)
    for string in strings:
        print(string)
