from elftools.elf.elffile import ELFFile

# Symbol binding types
STB_TYPES = {
    0: "LOCAL",
    1: "GLOBAL",
    2: "WEAK",
    13: "LOPROC",
    15: "HIPROC"
}

# Symbol types
STT_TYPES = {
    0: "NOTYPE",
    1: "OBJECT",
    2: "FUNC",
    3: "SECTION",
    4: "FILE",
    5: "COMMON",
    6: "TLS",
    13: "LOPROC",
    14: "HIOS",
    15: "HIPROC"
}

def get_symbol_bind(info):
    """Get binding type from st_info container"""
    # Handle Container object - access the bind attribute directly
    try:
        bind = info.bind if hasattr(info, 'bind') else (info >> 4 if isinstance(info, int) else int(str(info)) >> 4)
        return STB_TYPES.get(bind, f"UNKNOWN({bind})")
    except:
        return "UNKNOWN"

def get_symbol_type(info):
    """Get type from st_info container"""
    # Handle Container object - access the type attribute directly
    try:
        sym_type = info.type if hasattr(info, 'type') else (info & 0xF if isinstance(info, int) else int(str(info)) & 0xF)
        return STT_TYPES.get(sym_type, f"UNKNOWN({sym_type})")
    except:
        return "UNKNOWN"

def get_section_name(shndx):
    """Convert section index to readable name"""
    try:
        # Convert Container to int
        shndx_val = int(shndx) if not isinstance(shndx, str) else shndx
        
        if isinstance(shndx_val, str):
            return shndx_val
        
        if shndx_val == 0:
            return "UND"
        elif shndx_val == 0xfff1:
            return "ABS"
        elif shndx_val == 0xfff2:
            return "COM"
        elif shndx_val >= 0xff00:
            return f"RSV[0x{shndx_val:x}]"
        return str(shndx_val)
    except:
        return str(shndx)

def get_symbol_visibility(other):
    """Convert st_other field to visibility string"""
    try:
        # Convert Container to int
        other_val = int(other)
        visibility = other_val & 0x3
        
        if visibility == 0:
            return "DEFAULT"
        elif visibility == 1:
            return "INTERNAL"
        elif visibility == 2:
            return "HIDDEN"
        elif visibility == 3:
            return "PROTECTED"
        else:
            return f"UNKNOWN({visibility})"
    except:
        return "DEFAULT"

def display_symbol_table(filename):
    try:
        with open(filename, 'rb') as f:
            elf = ELFFile(f)
            
            print("================ Symbol Table ===========")
            
            symbol_tables = []
            for section in elf.iter_sections():
                if section['sh_type'] in ['SHT_SYMTAB', 'SHT_DYNSYM']:
                    symbol_tables.append((section.name, section))
            
            if not symbol_tables:
                print("No symbol tables found")
                return
            
            for table_name, symtab in symbol_tables:
                print(f"\n{table_name} contains {symtab.num_symbols()} entries:")
                print("-" * 100)
                
                for i, symbol in enumerate(symtab.iter_symbols()):
                    try:
                        # Access Container attributes properly
                        value = symbol['st_value']
                        size = symbol['st_size'] 
                        other = symbol['st_other']
                        shndx = symbol['st_shndx']
                        info = symbol['st_info']
                        
                        value_str = f"0x{value:016x}" if elf.elfclass == 64 else f"0x{value:08x}"
                        
                        print(f"{i}")
                        print(f"    Value: {value_str}")
                        print(f"    Size: {size}")
                        print(f"    Bind: {get_symbol_bind(info)}")
                        print(f"    Type: {get_symbol_type(info)}")
                        print(f"    Other: {get_symbol_visibility(other)}")
                        print(f"    Shndx: {get_section_name(shndx)}")
                        print(f"    Name: {symbol.name or ''}")
                        print()
                              
                    except Exception as e:
                        print(f"Error processing symbol {i}: {str(e)}")
                        continue
                        
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return False
    except Exception as e:
        print(f"Error analyzing ELF file: {e}")
        return False
    
    return True