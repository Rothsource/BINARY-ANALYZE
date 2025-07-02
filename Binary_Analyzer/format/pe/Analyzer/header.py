import pefile
import time

def File_Header(file_path):
    try:
        # Fix: Remove quotes around file_path variable
        pe = pefile.PE(file_path)
        
        # Access the Image File Header (COFF Header)
        file_header = pe.FILE_HEADER

        print("\n")
        print("="*20 + " FILE HEADER (COFF HEADER) " + "="*20)
        print(f"Machine:                             {hex(file_header.Machine)} ({pefile.MACHINE_TYPE.get(file_header.Machine, 'Unknown')})")
        print(f"Number of sections:                  {file_header.NumberOfSections}")
        
        # Fix: Proper timestamp conversion
        timestamp_str = time.ctime(file_header.TimeDateStamp) if file_header.TimeDateStamp else 'N/A'
        print(f"Time date stamp:                     {file_header.TimeDateStamp} ({timestamp_str})")
        
        print(f"Pointer to symbol table:             {hex(file_header.PointerToSymbolTable)}")
        print(f"Number of symbols:                   {file_header.NumberOfSymbols}")
        print(f"Size of optional header:             {file_header.SizeOfOptionalHeader}")
        print(f"Characteristics:                     {hex(file_header.Characteristics)}")
        
        # Print characteristics flags
        print("Characteristics flags:")
        characteristics = [
            (0x0001, "IMAGE_FILE_RELOCS_STRIPPED"),
            (0x0002, "IMAGE_FILE_EXECUTABLE_IMAGE"),
            (0x0004, "IMAGE_FILE_LINE_NUMBERS_STRIPPED"),
            (0x0008, "IMAGE_FILE_LOCAL_SYMS_STRIPPED"),
            (0x0010, "IMAGE_FILE_AGGR_WS_TRIM"),
            (0x0020, "IMAGE_FILE_LARGE_ADDRESS_AWARE"),
            (0x0080, "IMAGE_FILE_32BIT_MACHINE"),
            (0x0100, "IMAGE_FILE_DEBUG_STRIPPED"),
            (0x0200, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP"),
            (0x0400, "IMAGE_FILE_NET_RUN_FROM_SWAP"),
            (0x0800, "IMAGE_FILE_SYSTEM"),
            (0x1000, "IMAGE_FILE_DLL"),
            (0x2000, "IMAGE_FILE_UP_SYSTEM_ONLY"),
            (0x4000, "IMAGE_FILE_BYTES_REVERSED_HI")
        ]
        
        for flag, name in characteristics:
            if file_header.Characteristics & flag:
                print(f"  - {name}")
        
        # Close the PE file
        pe.close()
        
    except Exception as e:
        print(f"Error analyzing file header: {e}")