from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section

def Section(filename):
    try:
        with open(filename, 'rb') as f:
            elffile = ELFFile(f)
            
            # Print Section Information
            print("================ SECTIONS =================")
            sections = list(elffile.iter_sections())
            print(f"number_of_sections: {len(sections)}")
            
            #section_names = [section.name for section in sections if section.name]
            for i in sections:
                if i.name:
                    print("  ", i.name)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return False
    except Exception as e:
        print(f"Error analyzing ELF file: {e}")
        return False
    
    return True