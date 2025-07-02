import pefile
from .share import generate_hashes

def Sections_Headers(file_path):
    try:
        pe = pefile.PE(file_path)
        print("\n")
        print("="*25+" SECTION HEADER " + "="*25)
        for index, section in enumerate(pe.sections):
            
            name = section.Name.decode('utf-8').rstrip('\x00')
            
            print(f"Section {index+1}: {name}")
            print(f"   Virtual Size: {section.Misc_VirtualSize} (0x{section.Misc_VirtualSize:x})")
            print(f"   Virtual Address: 0x{section.VirtualAddress:x}")
            print(f"   Size of Raw Data: {section.SizeOfRawData} (0x{section.SizeOfRawData:x})")
            print(f"   Pointer to Relocations: 0x{section.PointerToRelocations:x}")
            print(f"   Pointer to Line Numbers: 0x{section.PointerToLinenumbers:x}")
            print(f"   Number of Relocations: {section.NumberOfRelocations}")
            print(f"   Number of Line Numbers: {section.NumberOfLinenumbers}")
            
            print(f"   Entropy: {section.get_entropy()}")
            hash_result = generate_hashes(section.get_data())
            for i, j in hash_result.items():
                print(f"   {i}: {j}")
                
            print(f"   Characteristics: 0x{section.Characteristics:x}")
            
            # Decode characteristics
            char_flags = decode_characteristics(section.Characteristics)
            if char_flags:
                print(f"   Characteristics Flags: {', '.join(char_flags)}")
            else:
                print(f"   Characteristics Flags: None")
            print("\n")
            
        pe.close()
    
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except pefile.PEFormatError:
        print(f"Error: '{file_path}' is not a valid PE file.")
    except Exception as e:
        print(f"Error analyzing file: {str(e)}")

def decode_characteristics(characteristics):
    """Decode section characteristics into readable flags"""
    flags = []
    
    # Section characteristic flags
    char_flags = {
        0x00000020: "IMAGE_SCN_CNT_CODE",
        0x00000040: "IMAGE_SCN_CNT_INITIALIZED_DATA", 
        0x00000080: "IMAGE_SCN_CNT_UNINITIALIZED_DATA",
        0x00000200: "IMAGE_SCN_LNK_INFO",
        0x00000800: "IMAGE_SCN_LNK_REMOVE",
        0x00001000: "IMAGE_SCN_LNK_COMDAT",
        0x00008000: "IMAGE_SCN_GPREL",
        0x00020000: "IMAGE_SCN_MEM_PURGEABLE",
        0x00040000: "IMAGE_SCN_MEM_16BIT",
        0x00080000: "IMAGE_SCN_MEM_LOCKED",
        0x00100000: "IMAGE_SCN_MEM_PRELOAD",
        0x01000000: "IMAGE_SCN_LNK_NRELOC_OVFL",
        0x02000000: "IMAGE_SCN_MEM_DISCARDABLE",
        0x04000000: "IMAGE_SCN_MEM_NOT_CACHED",
        0x08000000: "IMAGE_SCN_MEM_NOT_PAGED",
        0x10000000: "IMAGE_SCN_MEM_SHARED",
        0x20000000: "IMAGE_SCN_MEM_EXECUTE",
        0x40000000: "IMAGE_SCN_MEM_READ",
        0x80000000: "IMAGE_SCN_MEM_WRITE"
    }
    
    # Check each flag
    for flag_value, flag_name in char_flags.items():
        if characteristics & flag_value:
            flags.append(flag_name)
    
    return flags