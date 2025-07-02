from elftools.elf.elffile import ELFFile

def Program_Headers(filename):
    try:
        with open(filename, 'rb') as f:
            elffile = ELFFile(f)
            
            # Print Program Header Table
            print("=============== PROGRAM HEADER ==========")
            print()
            print(f"{'Type':<12} {'Offset':<10} {'VirtAddr':<12} {'PhysAddr':<12} {'FileSize':<10} {'MemSize':<10} {'Flags':<8} {'Align':<8}")
            print("-" * 88)
            
            for segment in elffile.iter_segments():
                # Format flags
                flags_str = ""
                if segment['p_flags'] & 0x1:  # PF_X
                    flags_str += "E"
                if segment['p_flags'] & 0x2:  # PF_W
                    flags_str += "W"
                if segment['p_flags'] & 0x4:  # PF_R
                    flags_str += "R"
                
                print(f"{segment['p_type']:<12} 0x{segment['p_offset']:06x}   "
                      f"0x{segment['p_vaddr']:08x}   0x{segment['p_paddr']:08x}   "
                      f"0x{segment['p_filesz']:06x}   0x{segment['p_memsz']:06x}   "
                      f"{flags_str:<8} 0x{segment['p_align']:x}")
            
            print()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return False
    except Exception as e:
        print(f"Error analyzing ELF file: {e}")
        return False
    
    return True