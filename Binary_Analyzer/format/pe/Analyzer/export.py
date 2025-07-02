import pefile

def Exports(file_path):
    """
    Analyze and display export functions from a PE file
    """
    try:
        # Load the PE file
        pe = pefile.PE(file_path)
        print("\n")
        print("="*27 + "EMPORTS"+ "="*27)
        
        # Check if the file has exports
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            print("No exports found in this PE file.")
            return
        
        # Get export directory
        export_dir = pe.DIRECTORY_ENTRY_EXPORT
        
        # Display export table information
        print(f"Export Table Information:")
        print(f"  DLL Name: {export_dir.name.decode('utf-8') if export_dir.name else 'N/A'}")
        print(f"  Base Ordinal: {export_dir.struct.Base}")
        print(f"  Number of Functions: {export_dir.struct.NumberOfFunctions}")
        print(f"  Number of Names: {export_dir.struct.NumberOfNames}")
        print(f"  Timestamp: {export_dir.struct.TimeDateStamp}")
        print()
        
        
        # Iterate through exports
        for exp in export_dir.symbols:
            # Calculate ordinal (Base + index)
            ordinal = export_dir.struct.Base + exp.ordinal
            
            if exp.name:
                # Function exported by name
                func_name = exp.name.decode('utf-8')
                print(f"Function: {func_name}")
                print(f"  Ordinal: {ordinal}")
                print(f"  RVA: 0x{exp.address:08x}")
                
                # Check if it's a forwarded export
                if exp.forwarder:
                    print(f"  Forwarder: {exp.forwarder.decode('utf-8')}")
                else:
                    # Convert RVA to file offset for non-forwarded exports
                    try:
                        file_offset = pe.get_offset_from_rva(exp.address)
                        print(f"  File Offset: 0x{file_offset:08x}")
                    except:
                        pass
                print()
            else:
                # Function exported by ordinal only
                print(f"Ordinal-only export:")
                print(f"  Ordinal: {ordinal}")
                print(f"  RVA: 0x{exp.address:08x}")
                if exp.forwarder:
                    print(f"  Forwarder: {exp.forwarder.decode('utf-8')}")
                print()
        
        # Close the PE file
        pe.close()
        
    except pefile.PEFormatError:
        print("Error: Invalid PE file format")
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found")
    except Exception as e:
        print(f"Error: {str(e)}")