import re

win_pattern = re.compile(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*')
unix_pattern = re.compile(r'/(?:[^/\0\s]+/)*[^/\0\s]*')

def extract_file_paths(strings):
    paths = set()

    for s in strings:
        paths.update(win_pattern.findall(s))
        paths.update(
            path for path in unix_pattern.findall(s)
            if len(path) > 3 and not path.startswith('//')
        )

    # Display results
    if not paths:
        print("No file paths found.")
    else:
        print("Found file paths:")
        for path in sorted(paths):
            print(path)
