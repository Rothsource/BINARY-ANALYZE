from .Analyzer import extract_domains, extract_emails, extractstrings, extract_ips, extract_meaningful_sentences, extract_file_paths, extract_ports, extract_registry_keys, extract_urls, all

def analyze_strings(file_path, args):
    strings = extractstrings(file_path, min_length=4)
    if args.urllink:
        extract_urls(strings)
    if args.domain:
        extract_domains(strings)
    if args.email:
        extract_emails(strings)
    if args.ipadd:
        extract_ips(strings)
    if args.path:
        extract_file_paths(strings)
    if args.port:
        extract_ports(strings)
    if args.rkeys:
        extract_registry_keys(strings)
    if args.meaningful:
        extract_meaningful_sentences(strings)
    if args.all:
        all(strings)
    if not any([
        args.urllink, args.domain, args.email, args.ipadd,
        args.path, args.port, args.rkeys,
        args.meaningful, args.all
    ]):
        print("Error: Look at your file direcotry or CLI (-h)")