import pefile

def Sections(file_path):
    try:
        pe = pefile.PE(file_path)
        print("\n")
        print("="*30 + " Sections " + "="*30)
        print(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
        
        for section in pe.sections:
            name = section.Name.decode('utf-8').rstrip('\x00')
            print(f"  {name}")
        
        # No need for pe.close(), pefile.PE does not have a close() method
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except pefile.PEFormatError:
        print(f"Error: '{file_path}' is not a valid PE file.")
    except Exception as e:
        print(f"Error analyzing file: {str(e)}")