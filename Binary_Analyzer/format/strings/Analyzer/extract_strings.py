def extractstrings(file_path, min_length=4):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return []

    strings = []
    current_string = ""

    for byte in data:
        if 32 <= byte <= 126:
            current_string += chr(byte)
        else:
            if len(current_string) >= min_length:
                strings.append(current_string)
            current_string = ""

    if len(current_string) >= min_length:
        strings.append(current_string)

    return strings