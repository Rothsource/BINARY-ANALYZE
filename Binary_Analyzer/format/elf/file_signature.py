from .Analyzer import Program_Headers, Header, Section, Sections_Header, display_symbol_table

def analyzer_elf(file_path, args):
    if args.sheader:
        Sections_Header(file_path)
    if args.header:
        Header(file_path)
    if args.pheader:
        Program_Headers(file_path)
    if args.section:
        Section(file_path)
    if args.stable:
        display_symbol_table(file_path)    
    if not any([
        args.sheader, args.header, args.section, args.stable,
        args.pheader,
    ]):
        print("Error: Look at your file direcotry or CLI (-h)")