from .Analyzer import DOS, DOS_Stub, File_Header, optional_header, Sections, Sections_Headers, Resource, Import, Exports, data_directory

def analyze_pe(file_path, args):
    if args.dos:
        DOS(file_path)
    if args.dosstub:
        DOS_Stub(file_path)
    if args.header:
        File_Header(file_path)
    if args.oheader:
        optional_header(file_path)  
    if args.section:
        Sections(file_path)
    if args.sheader:
        Sections_Headers(file_path)
    if args.resource:
        Resource(file_path)
    if args.import_:
        Import(file_path)
    if args.exports:
        Exports(file_path)
    if args.ddirectory:
        data_directory(file_path)

    if not any([
        args.dos, args.dosstub, args.header, args.oheader,
        args.section, args.sheader, args.resource,
        args.import_, args.exports, args.ddirectory
    ]):
        print("Error: Look at your file direcotry or CLI (-h)")
