import argparse
from core.file_detector import detect_file_type
from format.pe import analyze_pe
from format.elf import analyzer_elf
from format.strings import analyze_strings

parser = argparse.ArgumentParser(description="Universal Binary Analyzer")
parser.add_argument("-f", "--file", required=True, help="Path to the binary file")
parser.add_argument("-d", "--dos", action="store_true", help="Run DOS analysis")
parser.add_argument("-ds", "--dosstub", action="store_true", help="Run DOS Stub analysis")
parser.add_argument("-he", "--header", action="store_true", help="Analyze File Header")
parser.add_argument("-sh", "--sheader", action="store_true", help="Analyze Section Headers")
parser.add_argument("-r", "--resource", action="store_true", help="Analyze Resources")
parser.add_argument("-i", "--import_", action="store_true", help="Analyze Imports")
parser.add_argument("-e", "--exports", action="store_true", help="Analyze Exports")
parser.add_argument("-d2", "--ddirectory", action="store_true", help="Analyze Data Directory")
parser.add_argument("-s", "--section", action="store_true", help="Analyze Sections")
parser.add_argument("-o", "--oheader", action="store_true", help="Analyze Optional Header")


parser.add_argument("-ph","--pheader", action="store_true", help="ELF: Program Headers")
parser.add_argument("-st", "--stable" , action="store_true", help="ELF: Symbol Table")

parser.add_argument("-str", "--strings", action="store_true", help="Extract strings from binary")
parser.add_argument("-url", "--urllink", action="store_true", help="Analyze URLs in file")
parser.add_argument("-dm", "--domain", action="store_true", help="Analyze Domains in file")
parser.add_argument("-em", "--email", action="store_true", help="Analyze Email in file")
parser.add_argument("-ip", "--ipadd", action="store_true", help="Analyze IP Address in file")
parser.add_argument("-pt", "--path", action="store_true", help="Analyze Path in file")
parser.add_argument("-po", "--port", action="store_true", help="Analyze Port in file")
parser.add_argument("-rk", "--rkeys", action="store_true", help="Analyze Registry Keys in file")
parser.add_argument("-mf", "--meaningful", action="store_true", help="Analyze MeaningFul Words in file")
parser.add_argument("-a", "--all", action="store_true", help="Analyze All Strings in file")

args = parser.parse_args()
file_type = detect_file_type(args.file)

if args.strings:
    analyze_strings(args.file, args)
elif file_type == "PE":
    analyze_pe(args.file, args)

elif file_type == "ELF":
    analyzer_elf(args.file, args)
else:
    print("Unsupported file type")
