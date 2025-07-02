import pefile

def data_directory(file_path):
    try:
        # Load the PE file
        pe = pefile.PE(file_path)
        
        # Data directory names
        directory_names = [
            "Export Table",
            "Import Table", 
            "Resource Table",
            "Exception Table",
            "Certificate Table",
            "Base Relocation Table",
            "Debug",
            "Architecture",
            "Global Ptr",
            "TLS Table",
            "Load Config Table",
            "Bound Import",
            "IAT",
            "Delay Import Descriptor",
            "COM+ Runtime Header",
            "Reserved"
        ]

        print("\n")
        print("="*25 + " Data Directory " + "="*25)
        print(f"{'Index':<3} {'Directory Name':<25} {'Virtual Address':<15} {'Size':<15}")
        
        # Iterate through data directory entries
        for i, directory in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
            dir_name = directory_names[i] if i < len(directory_names) else f"Reserved[{i}]"
            
            virtual_addr = f"0x{directory.VirtualAddress:08X}" if directory.VirtualAddress else "Not Present"
            size = f"0x{directory.Size:08X}" if directory.Size else "0"
            
            print(f"  {i+1:<3} {dir_name:<25} {virtual_addr:<15} {size:<15}")
        
        pe.close()
        
    except Exception as e:
        print(f"Error parsing PE file: {e}")