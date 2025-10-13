import glob
import os
import tempfile

from ptdataclasses.argumentoptions import ArgumentOptions


from ptlibs import ptprinthelper

from urllib.parse import urlparse


def get_star_position( url:str) -> tuple[int, str]:
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

def shorten_url_middle(url: str, max_len: int) -> str:
    """
    Shorten a URL by keeping the domain, start, and end of the path, inserting '...' in the middle if needed.
    
    Rules:
    1. If the full URL fits within max_len, return it unchanged.
    2. If it doesn't fit, keep the first and last path segments with '...' between.
    3. If even that is too long, truncate from the middle of the path as a fallback.
    """
    if not url:
        return ""

    parsed = urlparse(url)
    
    # Build prefix (scheme + domain)
    if parsed.netloc:
        prefix = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else parsed.netloc
    elif parsed.scheme:
        prefix = f"{parsed.scheme}://"
    else:
        prefix = ""

    path = (parsed.path or "").strip("/")
    segments = path.split("/") if path else []

    # Full URL
    full_url = f"{prefix}/{path}" if prefix else path
    if len(full_url) <= max_len:
        return full_url  # fits, no shortening needed

    # If no path, fallback to prefix only
    if not segments:
        return prefix[:max_len]

    # First and last segments
    first = segments[0]
    last = segments[-1]

    # Attempt first + ... + last
    if len(segments) > 2:
        candidate = f"{prefix}/{first}/.../{last}" if prefix else f"{first}/.../{last}"
    else:
        candidate = f"{prefix}/{first}/{last}" if len(segments) > 1 else f"{prefix}/{first}" if prefix else first

    if len(candidate) <= max_len:
        return candidate

    # Fallback: truncate path from the end
    remain = max(max_len - len(prefix) - 4, 1)  # 4 chars for '/...'
    short_path = f"...{path[-remain:]}"
    return f"{prefix}/{short_path}" if prefix else short_path
def print_configuration( args: ArgumentOptions, keyspace) -> None:
    """
    Print the scan configuration and settings to the output.

    Args:
        args (ArgumentOptions): Parsed and processed command-line arguments.
    """
    ptprinthelper.ptprint( ptprinthelper.out_title_ifnot("Settings overview", args.json))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"URL................: {args.url}", "INFO", args.json)) #args.original_url
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Discovery-type.....: Brute force", "INFO", args.json or args.wordlist or args.parse_only or args.backup_all))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Discovery-type.....: Complete backups only", "INFO", args.json or not args.backup_all))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Discovery-type.....: Dictionary", "INFO", args.json or not args.wordlist))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Discovery-type.....: Crawling", "INFO", args.json or not args.parse_only))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Wordlist...........: {str(args.wordlist)}", "INFO", args.json or not args.wordlist))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Extensions.........: {args.extensions}", "INFO", args.json))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Method.............: {args.method}", "INFO", args.json))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"String starts......: {args.begin_with}", "INFO", args.json or not args.begin_with))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Is in response.....: {args.string_in_response}", "INFO", args.json or not args.string_in_response))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Is not in response.: {args.string_not_in_response}", "INFO", args.json or not args.string_not_in_response))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Charset............: {''.join(args.charset)}", "INFO", args.json or args.wordlist or args.parse_only))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Length-min.........: {args.length_min}", "INFO", args.json or args.parse_only))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Length-max.........: {args.length_max}", "INFO", args.json or args.parse_only))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Keyspace...........: {keyspace}", "INFO", args.json or args.parse_only))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Delay..............: {args.delay}s", "INFO", args.json))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Threads............: {args.threads}", "INFO", args.json))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Recurse............: {args.recurse}", "INFO", args.json))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Parse content......: {args.parse}", "INFO", args.json))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Search for backups.: {args.backups}", "INFO", args.json))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Status code yes....: {args.status_code_yes}", "INFO", args.json))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Status code no.....: {args.status_code_no}", "INFO", args.json))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f" ", "", args.json))