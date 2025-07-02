import pefile

def get_subsystem_name(subsystem_value):
    """Helper function to get subsystem name from value"""
    subsystems = {
        0: "Unknown",
        1: "Native",
        2: "Windows GUI",
        3: "Windows Console",
        5: "OS/2 Console",
        7: "Posix Console",
        8: "Native Win9x Driver",
        9: "Windows CE GUI",
        10: "EFI Application",
        11: "EFI Boot Service Driver",
        12: "EFI Runtime Driver",
        13: "EFI ROM",
        14: "Xbox",
        16: "Windows Boot Application"
    }
    return subsystems.get(subsystem_value, f"Unknown ({subsystem_value})")

def get_dll_characteristics(dll_chars):
    """Helper function to decode DLL characteristics flags"""
    characteristics = []
    flags = {
        0x0001: "Reserved1",
        0x0002: "Reserved2", 
        0x0004: "Reserved4",
        0x0008: "Reserved8",
        0x0020: "HIGH_ENTROPY_VA",
        0x0040: "DYNAMIC_BASE",
        0x0080: "FORCE_INTEGRITY",
        0x0100: "NX_COMPAT",
        0x0200: "NO_ISOLATION",
        0x0400: "NO_SEH",
        0x0800: "NO_BIND",
        0x1000: "APPCONTAINER",
        0x2000: "WDM_DRIVER",
        0x4000: "GUARD_CF",
        0x8000: "TERMINAL_SERVER_AWARE"
    }
    
    for flag, name in flags.items():
        if dll_chars & flag:
            characteristics.append(name)
    
    return ", ".join(characteristics) if characteristics else "None"

def optional_header(file_path):
    try:
        # Load the PE file
        pe = pefile.PE(file_path)
        
        # Get the optional header
        optional_hdr = pe.OPTIONAL_HEADER
        
        # Determine PE format type based on Magic field
        is_pe32_plus = optional_hdr.Magic == 0x20b
        pe_format = "PE32+" if is_pe32_plus else "PE32"

        print("\n")
        print("="*25 + " Optional Header " + "="*25)
    
        # Print common fields (same in both PE32 and PE32+)
        print(f"{'Magic':<30}: 0x{optional_hdr.Magic:04X} ({pe_format})")
        print(f"{'MajorLinkerVersion':<30}: {optional_hdr.MajorLinkerVersion}")
        print(f"{'MinorLinkerVersion':<30}: {optional_hdr.MinorLinkerVersion}")
        print(f"{'SizeOfCode':<30}: 0x{optional_hdr.SizeOfCode:08X} ({optional_hdr.SizeOfCode} bytes)")
        print(f"{'SizeOfInitializedData':<30}: 0x{optional_hdr.SizeOfInitializedData:08X} ({optional_hdr.SizeOfInitializedData} bytes)")
        print(f"{'SizeOfUninitializedData':<30}: 0x{optional_hdr.SizeOfUninitializedData:08X} ({optional_hdr.SizeOfUninitializedData} bytes)")
        print(f"{'AddressOfEntryPoint':<30}: 0x{optional_hdr.AddressOfEntryPoint:08X}")
        print(f"{'BaseOfCode':<30}: 0x{optional_hdr.BaseOfCode:08X}")
        
        # BaseOfData only exists in PE32 (4 bytes), not in PE32+
        if not is_pe32_plus and hasattr(optional_hdr, 'BaseOfData'):
            print(f"{'BaseOfData':<30}: 0x{optional_hdr.BaseOfData:08X} (PE32 only)")
        elif is_pe32_plus:
            print(f"{'BaseOfData':<30}: N/A (Not present in PE32+)")
        
        # ImageBase: 4 bytes in PE32, 8 bytes in PE32+
        if is_pe32_plus:
            print(f"{'ImageBase':<30}: 0x{optional_hdr.ImageBase:016X} (8 bytes)")
        else:
            print(f"{'ImageBase':<30}: 0x{optional_hdr.ImageBase:08X} (4 bytes)")
        
        # Common fields continue
        print(f"{'SectionAlignment':<30}: 0x{optional_hdr.SectionAlignment:08X}")
        print(f"{'FileAlignment':<30}: 0x{optional_hdr.FileAlignment:08X}")
        print(f"{'MajorOperatingSystemVersion':<30}: {optional_hdr.MajorOperatingSystemVersion}")
        print(f"{'MinorOperatingSystemVersion':<30}: {optional_hdr.MinorOperatingSystemVersion}")
        print(f"{'MajorImageVersion':<30}: {optional_hdr.MajorImageVersion}")
        print(f"{'MinorImageVersion':<30}: {optional_hdr.MinorImageVersion}")
        print(f"{'MajorSubsystemVersion':<30}: {optional_hdr.MajorSubsystemVersion}")
        print(f"{'MinorSubsystemVersion':<30}: {optional_hdr.MinorSubsystemVersion}")
        print(f"{'Win32VersionValue':<30}: 0")
        print(f"{'SizeOfImage':<30}: 0x{optional_hdr.SizeOfImage:08X} ({optional_hdr.SizeOfImage} bytes)")
        print(f"{'SizeOfHeaders':<30}: 0x{optional_hdr.SizeOfHeaders:08X} ({optional_hdr.SizeOfHeaders} bytes)")
        print(f"{'CheckSum':<30}: 0x{optional_hdr.CheckSum:08X}")
        print(f"{'Subsystem':<30}: 0x{optional_hdr.Subsystem:04X} ({get_subsystem_name(optional_hdr.Subsystem)})")
        print(f"{'DllCharacteristics':<30}: 0x{optional_hdr.DllCharacteristics:04X} ({get_dll_characteristics(optional_hdr.DllCharacteristics)})")
        
        # Stack and Heap sizes: 4 bytes in PE32, 8 bytes in PE32+
        if is_pe32_plus:
            print(f"{'SizeOfStackReserve':<30}: 0x{optional_hdr.SizeOfStackReserve:016X} ({optional_hdr.SizeOfStackReserve} bytes)")
            print(f"{'SizeOfStackCommit':<30}: 0x{optional_hdr.SizeOfStackCommit:016X} ({optional_hdr.SizeOfStackCommit} bytes)")
            print(f"{'SizeOfHeapReserve':<30}: 0x{optional_hdr.SizeOfHeapReserve:016X} ({optional_hdr.SizeOfHeapReserve} bytes)")
            print(f"{'SizeOfHeapCommit':<30}: 0x{optional_hdr.SizeOfHeapCommit:016X} ({optional_hdr.SizeOfHeapCommit} bytes)")
        else:
            print(f"{'SizeOfStackReserve':<30}: 0x{optional_hdr.SizeOfStackReserve:08X} ({optional_hdr.SizeOfStackReserve} bytes)")
            print(f"{'SizeOfStackCommit':<30}: 0x{optional_hdr.SizeOfStackCommit:08X} ({optional_hdr.SizeOfStackCommit} bytes)")
            print(f"{'SizeOfHeapReserve':<30}: 0x{optional_hdr.SizeOfHeapReserve:08X} ({optional_hdr.SizeOfHeapReserve} bytes)")
            print(f"{'SizeOfHeapCommit':<30}: 0x{optional_hdr.SizeOfHeapCommit:08X} ({optional_hdr.SizeOfHeapCommit} bytes)")
        
        # Final common fields
        print(f"{'LoaderFlags':<30}: 0x{optional_hdr.LoaderFlags:08X}")
        print(f"{'NumberOfRvaAndSizes':<30}: {optional_hdr.NumberOfRvaAndSizes}")
        
        pe.close()
        
    except Exception as e:
        print(f"Error parsing PE file: {e}")