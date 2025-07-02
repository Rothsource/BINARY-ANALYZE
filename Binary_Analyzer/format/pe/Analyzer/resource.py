import pefile
from .share import generate_hashes, calculate_entropy

def Resource(file_path):
    RESOURCE_TYPES = {
        1: "RT_CURSOR",
        2: "RT_BITMAP", 
        3: "RT_ICON",
        4: "RT_MENU",
        5: "RT_DIALOG",
        6: "RT_STRING",
        7: "RT_FONTDIR",
        8: "RT_FONT",
        9: "RT_ACCELERATOR",
        10: "RT_RCDATA",
        11: "RT_MESSAGETABLE",
        12: "RT_GROUP_CURSOR",
        14: "RT_GROUP_ICON",
        16: "RT_VERSION",
        17: "RT_DLGINCLUDE",
        19: "RT_PLUGPLAY",
        20: "RT_VXD",
        21: "RT_ANICURSOR",
        22: "RT_ANIICON",
        23: "RT_HTML",
        24: "RT_MANIFEST"
    }

    try:
        pe = pefile.PE(file_path)

        print("\n" + "="*23 + " RESOURCE INFO " + "="*23 + "\n")
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            print("No resources found in this PE file.")
            return

        resource_index = 1

        for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            resource_type = RESOURCE_TYPES.get(type_entry.id, f"UNKNOWN ({type_entry.id})")

            for name_entry in getattr(type_entry, 'directory', {}).entries:
                for lang_entry in getattr(name_entry, 'directory', {}).entries:
                    data_rva = lang_entry.data.struct.OffsetToData
                    size = lang_entry.data.struct.Size
                    lang = lang_entry.data.lang
                    sublang = lang_entry.data.sublang
                    codepage = lang_entry.data.struct.CodePage
                    #timestamp = lang_entry.data.struct.TimeDateStamp
                    
                    data = pe.get_data(data_rva, size)
                    entropy = calculate_entropy(data)
                    
                    print(f"{resource_index}")
                    print(f"Type\t{resource_type}")
                    print(f"Language\tUNKNOWN")
                    print(f"Codepage\tLatin 1 / Western European" if codepage == 1252 else f"Codepage\t{codepage}")
                    print(f"Size\t0x{size:x}")
                    
                   # try:
                   #     t = datetime.datetime.utcfromtimestamp(timestamp)
                   #     print(f"TimeDateStamp\t{t.strftime('%Y-%b-%d %H:%M:%S')}")
                   # except:
                   #     print(f"TimeDateStamp\tInvalid ({timestamp})")

                    print(f"Entropy\t{entropy:.5f}")
                    hash_result = generate_hashes(data)
                    for i, j in hash_result.items():
                        print(f"{i}: {j}")

                    print()
                    resource_index += 1

        pe.close()

    except pefile.PEFormatError:
        print("Error: Invalid PE file format")
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found")
    except Exception as e:
        print(f"Error: {str(e)}")   