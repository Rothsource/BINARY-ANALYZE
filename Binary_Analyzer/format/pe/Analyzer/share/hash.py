import hashlib

def generate_hashes(input_string):
    """Generate MD5, SHA1, SHA256, and SHA512 hashes for the given input string."""
    if isinstance(input_string, bytes):
        encoded_input = input_string
    else:
        encoded_input = input_string.encode('utf-8')
    
    hashes = {
        'MD5': hashlib.md5(encoded_input).hexdigest(),
        'SHA1': hashlib.sha1(encoded_input).hexdigest(),
        'SHA256': hashlib.sha256(encoded_input).hexdigest(),
        'SHA512': hashlib.sha512(encoded_input).hexdigest()
    }
    
    return hashes