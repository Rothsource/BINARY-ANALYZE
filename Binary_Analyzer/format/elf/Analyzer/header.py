from elftools.elf.elffile import ELFFile

def Header(filename):
    """Analyze ELF file structure and display comprehensive information"""
    
    try:
        with open(filename, 'rb') as f:
            elffile = ELFFile(f)
            
            # Print ELF Header
            print("================ ELF HEADER ===============")
            header = elffile.header
            
            print(f"Magic:                 {' '.join(f'{b:02x}' for b in header['e_ident']['EI_MAG'])}")
            print(f"Class:                 {header['e_ident']['EI_CLASS']} ({'64-bit' if header['e_ident']['EI_CLASS'] == 'ELFCLASS64' else '32-bit'})")
            print(f"Data:                  {header['e_ident']['EI_DATA']} ({'Little-endian' if header['e_ident']['EI_DATA'] == 'ELFDATA2LSB' else 'Big-endian'})")
            print(f"Version:               {header['e_ident']['EI_VERSION']}")
            print(f"OS/ABI:                {header['e_ident']['EI_OSABI']}")
            print(f"ABI Version:           {header['e_ident']['EI_ABIVERSION']}")
            print(f"Type:                  {header['e_type']}")
            print(f"Machine:               {header['e_machine']}")
            print(f"Version:               0x{header['e_version']}")
            print(f"Entry point address:   0x{header['e_entry']}")
            print(f"Program headers offset: {header['e_phoff']} bytes")
            print(f"Section headers offset: {header['e_shoff']} bytes")
            print(f"Flags:                 0x{header['e_flags']}")
            print(f"ELF header size:       {header['e_ehsize']} bytes")
            print(f"Program header size:   {header['e_phentsize']} bytes")
            print(f"Number of program headers: {header['e_phnum']}")
            print(f"Section header size:   {header['e_shentsize']} bytes")
            print(f"Number of section headers: {header['e_shnum']}")
            print(f"Section header string table index: {header['e_shstrndx']}")
            print()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
    except Exception as e:
        print(f"Error analyzing ELF file: {e}")