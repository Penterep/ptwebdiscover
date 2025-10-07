

import argparse
import sys
import glob
import os
import re

from ptlibs import ptnethelper, ptcharsethelper, ptprinthelper, ptjsonlib, ptmisclib
from ptlibs.ptprinthelper import ptprint
from ptlibs.threads import ptthreads, printlock, arraylock

from ptdataclasses.argumentoptions import ArgumentOptions

from utils.url import Url

from _version import __version__

def get_help():
    return [
        {"description": ["Web Source Discovery Tool"]},
        {"usage": ["ptwebdiscover <options>"]},
        {"Specials": [
            "Use '*' character in <url> to anchor tested location",
            "Use special wordlist with format of lines \"location::technology\" for identify of used techlologies",
            "For proxy authorization use -p http://username:password@address:port"]},
        {"usage_example": [
            "ptwebdiscover -u https://www.example.com",
            "ptwebdiscover -u https://www.example.com -ch lowercase,numbers,123abcdEFG*",
            "ptwebdiscover -u https://www.example.com -lx 4",
            "ptwebdiscover -u https://www.example.com -w",
            "ptwebdiscover -u https://www.example.com -w wordlist.txt",
            "ptwebdiscover -u https://www.example.com -w wordlist.txt --begin_with admin",
            "ptwebdiscover -u https://*.example.com -w wordlist.txt",
            "ptwebdiscover -u https://www.example.com/exam*.txt",
            "ptwebdiscover -u https://www.example.com -e \"\" bak old php~ php.bak",
            "ptwebdiscover -u https://www.example.com -E extensions.txt",
            "ptwebdiscover -u https://www.example.com -w -sn \"Page Not Found\""
            "ptwebdiscover -u https://www.example.com -arch",
            "ptwebdiscover -u https://www.example.com -arch noparams checked",
        ]},
        {"options": [
            ["-u",  "--url",                    "<url>",            "URL for test (usage of a star character as anchor)"],
            ["-ch", "--charsets",               "<charsets>",       "Specify charset for brute force (example: lowercase,uppercase,numbers,[custom_chars])"],
            ["",    "",                         "",                 "Modify wordlist (lowercase,uppercase,capitalize)"],
            ["-scy", "--status-code-yes",       "",                 "Include only sources returned with provided status codes"],
            ["-scn", "--status-code-no",        "",                 "Not include sources returned with provided status codes"],
            ["-src", "--source",                "<source>",         "Check for presence of only specified <source> (eg. -src robots.txt)"],
            ["-lm", "--length-min",             "<length-min>",     "Minimal length of brute-force tested string (default 1)"],
            ["-lx", "--length-max",             "<length-max>",     "Maximal length of brute-force tested string (default 6 bf / 99 wl"],
            ["-w",  "--wordlist",               "<filename>",       "Use specified wordlist(s)"],
            ["-pf", "--prefix",                 "<string>",         "Use prefix before tested string"],
            ["-sf", "--suffix",                 "<string>",         "Use suffix after tested string"],
            ["-bw", "--begin-with",             "<string>",         "Use only words from wordlist that begin with the specified string"],
            ["-ci", "--case-insensitive",       "",                 "Case insensitive items from wordlist"],
            ["-e",  "--extensions",             "<extensions>",     "Add extensions behind a tested string (\"\" for empty extension)"],
            ["-E",  "--extension-file",         "<filename>",       "Add extensions from default or specified file behind a tested string."],
            ["-r",  "--recurse",                "",                 "Recursive browsing of found directories"],
            ["-md", "--max_depth",              "<integer>",        "Maximum depth during recursive browsing (default: 20)"],
            ["-b",  "--backups",                "",                 "Search for backups of disclosed files"],
            ["-ba", "--backup-all",             "",                 "Search for backups of the website or db"],
            ["-P",  "--parse",                  "",                 "Parse HTML response for URLs discovery"],
            ["-Po", "--parse-only",             "",                 "Brute force method is disabled, crawling started on specified url"],
            ["-D",  "--directory",              "",                 "Add a slash at the ends of the strings too"],
            ["-nd", "--not-directories",        "<directories>",    "Not include listed directories when recursive browse run"],
            ["-sy", "--string-in-response",     "<string>",         "Print findings only if string in response (GET method is used)"],
            ["-sn", "--string-not-in-response", "<string>",         "Print findings only if string not in response (GET method is used)"],
            ["-sc", "--status-codes",           "<status-codes>",   "Ignore response with status codes (default 404)"],
            ["-d",  "--delay",                  "<miliseconds>",    "Delay before each request in seconds"],
            ["-T",  "--timeout",                "<miliseconds>",    "Manually set timeout (default 10000)"],
            ["-cl", "--content-length",         "<kilobytes>",      "Max content length to download and parse (default: 1000KB)"],
            ["-m",  "--method",                 "<method>",         "Use said HTTP method (default: HEAD)"],
            ["-se", "--scheme",                 "<scheme>",         "Use scheme when missing (default: http)"],
            ["-p",  "--proxy",                  "<proxy>",          "Use proxy (e.g. http://127.0.0.1:8080)"],
            ["-H",  "--headers",                "<headers>",        "Use custom headers"],
            ["-a",  "--user-agent",             "<agent>",          "Use custom value of User-Agent header"],
            ["-c",  "--cookie",                 "<cookies>",        "Use cookie (-c \"PHPSESSID=abc; any=123\")"],
            ["-A",  "--auth",                   "<name:pass>",      "Use HTTP authentication"],
            ["-rc", "--refuse-cookies",         "",                 "Do not use cookies set by application"],
            ["-t",  "--threads",                "<threads>",        "Number of threads (default 20)"],
            ["-wd", "--without-domain",         "",                 "Output of discovered sources without domain"],
            ["-wh", "--with-headers",           "",                 "Output of discovered sources with headers"],
            ["-ip", "--include-parameters",     "",                 "Include GET parameters and anchors to output"],
            ["-tr", "--tree",                   "",                 "Output as tree"],
            ["-o",  "--output",                 "<filename>",       "Output to file"],
            ["-S",  "--save",                   "<directory>",      "Save content localy"],
            ["-wdc","--without_dns_cache",      "",                 "Do not use DNS cache (example for /etc/hosts records)"],
            ["-tg", "--target",                 "<ip or host>",     "Use this target when * is in domain"],
            ["-nr", "--not-redirect",           "",                 "Do not follow redirects"],
            ["-s",  "--silent",                 "",                 "Do not show statistics in realtime"],
            ["-C",  "--cache",                  "",                 "Cache each request response to temp file"],
            ["-ne", "--non-exist",              "",                 "Check, if non existing pages return status code 200."],
            ["-vy", "-vuln-yes",                "",                 "Add provided VULN to JSON if source is found"],
            ["-vn", "-vuln-no",                 "",                 "Add provided VULN to JSON if source is not found"],
            ["-er", "--errors",                 "",                 "Show all errors"],
            ["-v",  "--version",                "",                 "Show script version"],
            ["-h",  "--help",                   "",                 "Show this help message"],
            ["-j",  "--json",                   "",                 "Output in JSON format"],
            ["-arch",  "--archive",             "",                 "Passive scan via webarchive, accepts optional arguments: (noparams, checked)"],
        ]},
    ]


def prepare_extensions(args: ArgumentOptions) -> list[str]:
    """
    Prepare the list of file extensions to test.

    Args:
        args (ArgumentOptions): Parsed and processed command-line arguments.

    Returns:
        list[str]: List of file extensions.
    """
    exts = ["", "/"] if args.directory else []
    if args.extensions_file:
        if args.extensions_file == True:
            args.wordlist = "extensions.txt"
        with open(args.extensions_file, encoding='utf-8', errors='ignore') as f:
            args.extensions += list(f)
            args.extensions = [item.strip() for item in args.extensions]
    if args.extensions:
        for extension in args.extensions:
            if not extension.startswith('.') and extension != "":
                extension = '.' + extension
            exts.append(extension)
    if exts == []:
        exts = [""]
    return exts


def expand_wordlist_patterns(wordlist_args: list[str], ptjsonlib: object, args: object) -> list[str]:
    """Expand wildcard patterns in wordlist arguments into actual file paths."""
    expanded = []
    for pattern in wordlist_args:
        # glob.glob s absolute path
        matches = [os.path.abspath(p) for p in glob.glob(pattern) if os.path.isfile(p)]
        if matches:
            expanded.extend(matches)
        else:
            if os.path.isfile(pattern):
                expanded.append(os.path.abspath(pattern))
            else:

                ptjsonlib.end_error(f"Wordlist not found: {pattern}", args.json)
                raise FileNotFoundError(f"Wordlist not found: {pattern}")
    return expanded

def merge_unique_wordlists(wordlist_paths: list[str]) -> str:
    """Merge multiple wordlist files into a single temporary file with unique entries."""
    unique_words = set()
    for wl_file in wordlist_paths:
        with open(wl_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line:
                    unique_words.add(line)
    tmp_fd, tmp_path = tempfile.mkstemp(prefix="ptwebdiscover_wordlist_", suffix=".txt")
    os.close(tmp_fd)
    with open(tmp_path, "w", encoding="utf-8") as out_f:
        for word in sorted(unique_words):
            out_f.write(word + "\n")
    return tmp_path

def get_star_position(url:str) -> tuple[int, str]:
    """
    Get the position of '*' in a URL and remove it.

    Args:
        url (str): Input URL.

    Returns:
        tuple[int, str]: (position index, URL without '*').
    """
    if "*" in url:
        position = url.find("*")
        url = url.replace(url[position], "")
        return (position, url)
    else:
        position = len(url) #url.rfind("/") + 1 # len(url)
        return (position, url)


def parse_args(scriptname: str) -> ArgumentOptions:
    SCRIPTNAME = scriptname
    parser = argparse.ArgumentParser(add_help=False, usage=f"{SCRIPTNAME} <options>")
    exclusive = parser.add_mutually_exclusive_group()
    exclusive.add_argument("-w",  "--wordlist", type=str, nargs="+")
    exclusive.add_argument("-src", "--source", type=str, nargs="+")
    parser.add_argument("-u",  "--url", type=str, required=False)
    parser.add_argument("-ch", "--charsets", type=str, nargs="+", default=[])
    parser.add_argument("-lm", "--length-min", type=int, default=1)
    parser.add_argument("-lx", "--length-max", type=int)
    parser.add_argument("-pf", "--prefix", type=str, default="")
    parser.add_argument("-sf", "--suffix", type=str, default="")
    parser.add_argument("-bw", "--begin-with", type=str)
    parser.add_argument("-b",  "--backups", action="store_true")
    parser.add_argument("-ba", "--backup-all", action="store_true")
    parser.add_argument("-e",  "--extensions", type=str, nargs="+", default=[])
    parser.add_argument("-E",  "--extensions-file", type=str)
    parser.add_argument("-r",  "--recurse", action="store_true")
    parser.add_argument("-md", "--max-depth", type=int, default=20)
    parser.add_argument("-P",  "--parse", action="store_true")
    parser.add_argument("-Po", "--parse-only", action="store_true")
    parser.add_argument("-D",  "--directory", action="store_true")
    parser.add_argument("-nd", "--not-directories", type=str, nargs="+", default=[])
    parser.add_argument("-ci", "--case-insensitive", action="store_true")
    parser.add_argument("-sy", "--string-in-response", type=str)
    parser.add_argument("-sn", "--string-not-in-response", type=str)
    parser.add_argument("-scy", "--status-code-yes", type=int, nargs="+", default=[])
    parser.add_argument("-scn", "--status-code-no", type=int, nargs="+", default=[400, 404, 407, 408, 410, 412, 415, 416, 418, 421, 423, 424, 425, 426, 427, 428, 429, 403])
    parser.add_argument("-m",  "--method", type=str.upper, default="HEAD", choices=["GET", "POST", "TRACE", "OPTIONS", "PUT", "DELETE", "HEAD", "DEBUG"])
    parser.add_argument("-se", "--scheme", type=str.lower, default="http", choices=["http", "https"])
    parser.add_argument("-d",  "--delay", type=int, default=0)
    parser.add_argument("-p",  "--proxy", type=str)
    parser.add_argument("-T",  "--timeout", type=int, default=10000)
    parser.add_argument("-cl", "--content-length", type=int, default=1000)
    parser.add_argument("-wdc","--without_dns_cache", action="store_true")
    parser.add_argument("-H",  "--headers", type=ptmisclib.pairs, nargs="+")
    parser.add_argument("-a", "--user-agent", type=str, default="Penterep Tools")
    parser.add_argument("-c",  "--cookie", type=str, default="")
    parser.add_argument("-rc", "--refuse-cookies", action="store_true")
    parser.add_argument("-nr", "--not-redirect", action="store_true", default=False)
    parser.add_argument("-tg", "--target", type=str, default="")
    parser.add_argument("-t",  "--threads", type=int, default=20)
    parser.add_argument("-wd", "--without-domain", action="store_true")
    parser.add_argument("-wh", "--with-headers", action="store_true")
    parser.add_argument("-ip", "--include-parameters", action="store_true")
    parser.add_argument("-tr", "--tree", action="store_true")
    parser.add_argument("-o",  "--output", type=str)
    parser.add_argument("-S",  "--save", type=str)
    parser.add_argument("-A",  "--auth", type=str)
    parser.add_argument("-ne", "--non-exist", action="store_true")
    parser.add_argument("-er", "--errors", action="store_true")
    parser.add_argument("-s",  "--silent", action="store_true")
    parser.add_argument("-C",  "--cache", action="store_true")
    parser.add_argument("-j",  "--json", action="store_true")
    parser.add_argument("-arch", "--archive",
        nargs="*",
        default=False,
        choices=["noparams", "checked"],
        type=lambda v: v.lower() if v.lower() in ["noparams", "checked"] else argparse.ArgumentTypeError(f"Invalid choice: {v}"),
    )
    parser.add_argument("-v",  "--version", action="version", version=f"{SCRIPTNAME} {__version__}")


    parser.add_argument("-vy",  "--vuln-yes", type=str)
    parser.add_argument("-vn",  "--vuln-no",  type=str)

    parser.add_argument("--socket-address",          type=str, default=None)
    parser.add_argument("--socket-port",             type=str, default=None)
    parser.add_argument("--process-ident",           type=str, default=None)

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    args = parser.parse_args()

    if args.archive == []:
        args.archive = True

    # if source exists and url is not set
    if args.source and not args.url:
        if not first.startswith(("http://", "https://")):
            ptjsonlib.PtJsonLib().end_error("Source is not a full URL. Add --url or make sure first source item is full URL.", args.json)
        first = args.source[0]
        args.url = first

    # Merge wordlists into one
    if args.wordlist:
        args.wordlist = expand_wordlist_patterns(args.wordlist, ptjsonlib.PtJsonLib(), args)
        if len(args.wordlist) > 1:
            args.wordlist = [merge_unique_wordlists(args.wordlist)]
    if args.wordlist is None:
        args.wordlist = []

    if not re.match(r"^https?://", args.url):
        ptjsonlib.PtJsonLib().end_error("Provided URL does not start with valid scheme.", args.json)

    # from init
    args.is_star: bool              = True if "*" in args.url else False
    args.auth: tuple                = tuple(args.auth.split(":")) if args.auth else None
    args.timeout: int               = args.timeout / 1000
    args.content_length: int        = args.content_length * 1000
    args.delay: int                 = args.delay / 1000

    args.original_url: str         = args.url
    args.url                       = ptnethelper.remove_slash_from_end_url(args.url) if not args.is_star else args.url
    args.url                       = Url(args.url).add_missing_scheme(args.scheme)
    args.target: str               = Url(args.target).add_missing_scheme(args.scheme)
    args.position, args.url        = get_star_position(args.url)

    _domain_with_protocol           = Url(args.url).get_domain_from_url(level=True, with_protocol=True)
    #input(_domain_with_protocol)
    args.is_star_in_domain          = True if args.is_star and args.position < len(_domain_with_protocol)+1 else False

    args.proxies: dict              = {"http": args.proxy, "https": args.proxy}
    args.headers: dict              = ptnethelper.get_request_headers(args)
    args.charset: list              = ptcharsethelper.get_charset(["lowercase"]) if not args.charsets and not args.wordlist else ptcharsethelper.get_charset(args.charsets)
    args.parse: bool                = args.parse or args.parse_only
    args.length_max: int            = args.length_max if args.length_max else 99 if args.wordlist else 6
    args.begin_with: str            = args.begin_with if args.begin_with else ""
    args.threads: int               = args.threads if not args.delay  else 1
    args.method: str                = args.method if not (args.string_in_response or args.string_not_in_response or args.parse or args.save) else "GET"
    args.extensions                 = prepare_extensions(args)

    check_args_combinations(args)

    return args

def check_args_combinations(args) -> None:
    """
    Validate that provided argument combinations are compatible.

    Raises errors for unsupported combinations (e.g., using '*' with backups).
    """

    ptjsonlib_ = ptjsonlib.PtJsonLib()
    if args.is_star:
        if args.backups or args.backup_all:
            ptjsonlib_.end_error("Cannot find backups with '*' character in url", args.json)
        if args.parse or args.parse_only:
            ptjsonlib_.end_error("Cannot use HTML parse with '*' character in url", args.json)
        if args.recurse:
            ptjsonlib_.end_error("Cannot use recursivity with '*' character in url",  args.json)
        if args.non_exist:
            ptjsonlib_.end_error("Cannot use -ne/--non-exist option with '*' character in url ", args.json)
    if args.is_star_in_domain:
        if args.extensions != [""] or args.extensions_file:
            ptjsonlib_.end_error("Cannot use extensions with '*' character in domain", args.json)
        if args.tree:
            ptjsonlib_.end_error("Cannot use tree output with '*' character in domain", args.json)
        if args.without_domain:
            ptjsonlib_.end_error("Cannot use output without domain with '*' character in domain", args.json)

    if args.backup_all and (args.parse_only or args.wordlist):
        ptjsonlib_.end_error("Cannot use -ba/--backup-all with -Po/--parse-only or -w/--wordlist options", args.json)

    if args.parse_only and args.wordlist:
        ptjsonlib.end_error("Cannot use -Po/--parse-only with -w/--wordlist option", args.json)

            #ptprinthelper.ptprint(" ", None)

    #if args.wordlist and (args.backup_all or args.parse_only):
    #        ptjsonlib_.end_error("Cannot use wordlist with parameters --parse-only and --backup-only", args.json)

