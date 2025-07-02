import pefile

def DOS(file_path):
    try:
        # Load the PE file - remove quotes around file_path variable
        pe = pefile.PE(file_path)
        
        # Access the DOS Header
        dos_header = pe.DOS_HEADER
        
        # Print DOS Header fields
        print("="*30 + " DOS HEADER " + "="*30)
        print(f"Magic number: {dos_header.e_magic.to_bytes(2, byteorder='little').decode('ascii')}")   
        print(f"Used bytes in last page:             {hex(dos_header.e_cblp)}")
        print(f"File size in pages:                  {dos_header.e_cp}")
        print(f"Number of relocations:               {dos_header.e_crlc}")
        print(f"Header size in paragraphs:           {dos_header.e_cparhdr}")
        print(f"Minimum extra paragraphs needed:     {dos_header.e_minalloc}")
        print(f"Maximum extra paragraphs needed:     {dos_header.e_maxalloc}")
        print(f"Initial (relative) SS:               {hex(dos_header.e_ss)}")
        print(f"Initial SP:                          {hex(dos_header.e_sp)}")
        print(f"Checksum:                            {hex(dos_header.e_csum)}")
        print(f"Initial IP:                          {hex(dos_header.e_ip)}")
        print(f"Initial (relative) CS:               {hex(dos_header.e_cs)}")
        print(f"Address of relocation table:         {hex(dos_header.e_lfarlc)}")
        print(f"Overlay number:                      {dos_header.e_ovno}")
        print(f"Address of new EXE header:           {hex(dos_header.e_lfanew)}")
        
        pe.close()
    except Exception as e:
        print(f"Error analyzing DOS header: {e}")