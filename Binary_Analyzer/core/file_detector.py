def detect_file_type(filename):
    """
    Detects if a file is PE or ELF format.
    
    Args:
        filename (str): Path to the file to analyze
        
    Returns:
        str: "PE", "ELF", "UNKNOWN", or "ERROR"
    """
    
    try:
        with open(filename, 'rb') as file:
            # Read first 4 bytes
            magic_bytes = file.read(4)
            
            if len(magic_bytes) < 4:
                return "ERROR: File too small"
            
            # Check for ELF signature: 0x7F454C46 (0x7F + "ELF")
            if (magic_bytes[0] == 0x7F and magic_bytes[1] == 0x45 and 
                magic_bytes[2] == 0x4C and magic_bytes[3] == 0x46):
                return "ELF"
            
            # Check for MZ signature (potential PE file)
            if magic_bytes[0] == 0x4D and magic_bytes[1] == 0x5A:
                # Found MZ, now check if it's actually PE
                
                # Read PE header offset from position 0x3C
                file.seek(0x3C)
                pe_offset_bytes = file.read(4)
                
                if len(pe_offset_bytes) < 4:
                    return "ERROR: Invalid DOS header"
                
                # Convert to integer (little-endian)
                pe_offset = int.from_bytes(pe_offset_bytes, 'little')
                
                # Validate PE offset
                file.seek(0, 2)  # Go to end
                file_size = file.tell()
                
                if pe_offset >= file_size or pe_offset < 0:
                    return "ERROR: Invalid PE offset"
                
                # Check PE signature at calculated offset
                file.seek(pe_offset)
                pe_signature = file.read(4)
                
                if len(pe_signature) < 4:
                    return "ERROR: Cannot read PE signature"
                
                # Check for PE\0\0 signature
                if (pe_signature[0] == 0x50 and pe_signature[1] == 0x45 and
                    pe_signature[2] == 0x00 and pe_signature[3] == 0x00):
                    return "PE"
                else:
                    return "UNKNOWN: DOS file but not PE"
            
            # Not ELF, not MZ/PE
            return "UNKNOWN"
            
    except FileNotFoundError:
        return "ERROR: File not found"
    except PermissionError:
        return "ERROR: Permission denied"
    except Exception as e:
        return f"ERROR: {str(e)}"


def is_pe_or_elf(filename):
    """
    Simple boolean check if file is PE or ELF.
    
    Args:
        filename (str): Path to file
        
    Returns:
        tuple: (is_pe_or_elf: bool, file_type: str)
    """
    
    file_type = detect_file_type(filename)
    
    if file_type == "PE" or file_type == "ELF":
        return file_type
    else:
        return file_type