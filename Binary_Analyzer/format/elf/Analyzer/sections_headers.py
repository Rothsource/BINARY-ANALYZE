from elftools.elf.elffile import ELFFile


def Sections_Header(filename):
    try:
        with open(filename, 'rb') as f:
            elffile = ELFFile(f)
            
            # Print Section Header Table
            sections = list(elffile.iter_sections())
            print("\n")
            print("=============== SECTIONS HEADER ===========")
            print(f"{'Nr':<3} {'Name':<20} {'Type':<15} {'Address':<14} {'Offset':<10} {'Size':<10} {'EntSize':<8} {'Flags':<8} {'Link':<6} {'Info':<6} {'Align':<8}")
            print("-" * 110)
            
            for i, section in enumerate(sections):
                # Format flags
                flags_str = ""
                if section['sh_flags'] & 0x1:  # SHF_WRITE
                    flags_str += "W"
                if section['sh_flags'] & 0x2:  # SHF_ALLOC
                    flags_str += "A"
                if section['sh_flags'] & 0x4:  # SHF_EXECINSTR
                    flags_str += "X"
                if section['sh_flags'] & 0x10:  # SHF_MERGE
                    flags_str += "M"
                if section['sh_flags'] & 0x20:  # SHF_STRINGS
                    flags_str += "S"
                if section['sh_flags'] & 0x40:  # SHF_INFO_LINK
                    flags_str += "I"
                if section['sh_flags'] & 0x80:  # SHF_LINK_ORDER
                    flags_str += "L"
                if section['sh_flags'] & 0x200:  # SHF_GROUP
                    flags_str += "G"
                if section['sh_flags'] & 0x400:  # SHF_TLS
                    flags_str += "T"
                
                print(f"{i:<3} {section.name:<20} {section['sh_type']:<15} "
                      f"0x{section['sh_addr']:08x}     0x{section['sh_offset']:06x}   "
                      f"0x{section['sh_size']:06x}   {section['sh_entsize']:<8} "
                      f"{flags_str:<8} {section['sh_link']:<6} {section['sh_info']:<6} "
                      f"{section['sh_addralign']:<8}")
            print()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return False
    except Exception as e:
        print(f"Error analyzing ELF file: {e}")
        return False
    
    return True