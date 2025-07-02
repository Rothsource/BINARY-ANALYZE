import math

def calculate_entropy(data):
    """Calculate entropy of byte data."""
    if not data:
        return 0.0
    entropy = 0
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count:
            p = count / len(data)
            entropy -= p * math.log2(p)
    return entropy