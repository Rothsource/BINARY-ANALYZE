import pefile


def Import(file_path):
    try:
        # Load the PE file
        pe = pefile.PE(file_path)

        print("\n")
        print("="*27 + "IMPORTS"+ "="*27)
        
        # Check if the file has imports
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            print("No imports found in this PE file.")
            return
        
        # Iterate through each imported DLL
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            print(f"DLL: {dll_name}")
            
            # Iterate through imported functions from this DLL
            for imp in entry.imports:
                if imp.name:
                    # Function imported by name
                    func_name = imp.name.decode('utf-8')
                    print(f"  Function: {func_name}")
                    print(f"    Address: 0x{imp.address:08x}")
                    if imp.ordinal:
                        print(f"    Ordinal: {imp.ordinal}")
                else:
                    # Function imported by ordinal only
                    print(f"  Ordinal: {imp.ordinal}")
                    print(f"    Address: 0x{imp.address:08x}")
        
        # Close the PE file
        pe.close()
        
    except pefile.PEFormatError:
        print("Error: Invalid PE file format")
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found")
    except Exception as e:
        print(f"Error: {str(e)}")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return False