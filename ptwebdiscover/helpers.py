import os
import re
import posixpath
import urllib
import requests
from backups import Backups
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import warnings
from utils.url import Url
from ptlibs import ptcharsethelper, ptprinthelper
from ptdataclasses.argumentoptions import ArgumentOptions
    
    
def add_cookies_to_headers(args: ArgumentOptions, response) -> None:
    """
    Add cookies to headers from cookie argument and from response.

    Args:
        args (ArgumentOptions): Parsed and processed command-line arguments.
    """

    cookies = args.cookie if args.cookie else ""
    try:
        for c in response.raw.headers.getlist('Set-Cookie'):
            cookies += c.split("; ")[0] + "; "
    except:
        pass
    if cookies:
        args.headers["Cookie"] = cookies


def check_website_and_method_availability(self):
    """
    Check the availability of the website and the HTTP method.

    Args:
        args (ArgumentOptions): Parsed and processed command-line arguments.

    Returns:
        requests.Response: The HTTP response object.
    """
    if self.findings.is_url_forbidden(self.target.url):
        self.ptjsonlib.end_error("The provided URL contains forbidden paths and cannot be tested.", self.args.json)

    url = self.target.domain_with_scheme + "/"
    if self.args.is_star_in_domain:
        url = url.replace("*", "foo-nonexistent-domain")
        try:
            response = self.scanner.send_request(url=url, method=self.args.method, headers=self.args.headers, proxies=self.args.proxies, verify=False, redirects=False, auth=self.args.auth, cache=self.args.cache, max_retries=0)
            if response.status_code:
                status_code = response.status_code
                self.counters.non_existing_domain_status = status_code
                if status_code == 200:
                    non_existing_domain_title = re.search(r"<title>(.*?)</title>", response.text, re.IGNORECASE | re.DOTALL).group(1).strip()
                    self.counters.non_existing_domain_title = ("<title>" + non_existing_domain_title + "</title>") if non_existing_domain_title else None
                    self.counters.non_existing_domain_redirect = True if len(response.history) > 0 else False
                    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Non-existing (sub)domain returned status code: {status_code}", "INFO", self.args.json))
                    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Non-existing (sub)domain returned title: {non_existing_domain_title}", "INFO", self.args.json))
                    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Domains that are returned with the same status code and title will not be displayed. Use -sy or -sn parameter.\n", "INFO", self.args.json))
        except Exception as e:
            self.counters.non_existing_domain_status = 999
            ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Non-existing (sub)domain is not responding. It's OK.\n", "INFO", self.args.json))
    else:
        try:
            response = self.scanner.send_request(url, method=self.args.method, headers=self.args.headers, proxies=self.args.proxies, verify=False, redirects=True, auth=self.args.auth, cache=self.args.cache)

            if response.status_code == 405 or response.status_code == 501:
                self.ptjsonlib.end_error("HTTP method not supported. Use -m option for select another one.", self.args.json)

            url = Url(response.url)
            domain = url.get_domain_from_url(level=True, with_protocol=False)
            if domain != self.target.domain:
                self.ptjsonlib.end_error(f"Redirected to another domain: {domain}", self.args.json)

            if not self.args.refuse_cookies:
                add_cookies_to_headers(self.args, response)

            modify_scheme_when_redirect_from_http_to_https(self, response)
        
        except Exception as e:
            self.ptjsonlib.end_error("Server is not available", condition=self.args.json, details=str(e))


def modify_scheme_when_redirect_from_http_to_https(parent, response) -> None:
    """
    Modify the scheme of the URL from http to https when a redirect occurs.

    Args:
        args (ArgumentOptions): Parsed and processed command-line arguments.
        response (requests.Response): The HTTP response object.

    Returns:
        tuple[str, int]: Updated URL and position of the change.
    """
    if response.history and response.history[0].url.startswith("http://") and response.url.startswith("https://"):
        parent.target.url = parent.target.url.replace("http://", "https://", 1)
        parent.target.domain_with_scheme = parent.target.domain_with_scheme.replace("http://", "https://", 1)
        parent.target.scheme = "https"
        parent.args.position += 1
        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Scheme changed to HTTPS because redirect was detected.\n", "WARNING", parent.args.json))


def prepare_wordlist(self) -> tuple[int, list[str]]:
    """
    Load and process the wordlist(s) according to charset and filters.

    Args:
        self (PtWebDiscover): The PtWebDiscover instance.

    Returns:
        tuple[int, list[str]]: (keyspace size, prepared wordlist).
    """
    
    wordlist_complete = [""]
    try:
        for wl in self.args.wordlist:
            with open(wl, encoding='utf-8', errors='ignore') as f:
                wordlist = list(f)
                if self.args.archive:
                    wordlist = [item.strip() for item in wordlist if item]
                else:
                    wordlist = [item.strip() for item in wordlist if item.startswith(self.args.begin_with) and len(item) >= self.args.length_min and len(item) <= self.args.length_max]
            if self.args.case_insensitive or "lowercase" in self.args.charsets:
                wordlist = [item.lower() for item in wordlist]
                wordlist_complete += wordlist
            if not self.args.case_insensitive and "uppercase" in self.args.charsets:
                wordlist = [item.upper() for item in wordlist]
                wordlist_complete += wordlist
            if not self.args.case_insensitive and "capitalize" in self.args.charsets:
                wordlist = [item.capitalize() for item in wordlist]
                wordlist_complete += wordlist
            if not self.args.case_insensitive and not "lowercase" in self.args.charsets and not "uppercase" in self.args.charsets and not "capitalize" in self.args.charsets:
                wordlist_complete += wordlist
        wordlist_complete = list(dict.fromkeys(wordlist_complete))
        return wordlist_complete

    except FileNotFoundError as e:
        self.ptjsonlib.end_error(f"Wordlist {e.filename} not found", args.json)
    except PermissionError as e:
        self.ptjsonlib.end_error(f"Do not have permissions to open {e.filename}", args.json)

def get_unique_list(items: list) -> list:
    seen = set()
    return [x for x in items if not (x in seen or seen.add(x))]

def prepare_sources(self) -> list[str]:
    """
    Prepare sources provided by the -src parameter.

    Args:
        self (PtWebDiscover): The PtWebDiscover instance.
    Returns:
        list[str]: List of prepared sources.
    """
    sources = []
    url = None
    for src in self.args.source:
        # Absolute URL
        if src.startswith(("http://", "https://")):
            parsed = urllib.parse.urlparse(src)
            base = f"{parsed.scheme}://{parsed.netloc}"
            path = parsed.path.lstrip("/")

            if self.target.domain_with_scheme != base:
                self.ptjsonlib.end_error(f"Warning: Source {src} has different domain than target {self.target.url}.", self.args.json)
            if url and url != base:
                self.ptjsonlib.end_error(f"Warning: Source {src} has different domain than previous source {url}", self.args.json)
            url = base

            if src and src not in sources:
                sources.append(path)
        # Relative path
        else:
            if src not in sources:
                sources.append(src.lstrip("/"))

        if not self.target.url:
            if not url:
                self.ptjsonlib.end_error(f"When using -src with relative paths, the -u parameter must be also provided.", self.args.json)
            else:
                self.target.url = url + "/"
                self.target.domain = url.split("://")[1]
                self.target.domain_with_scheme = url
                self.target.scheme = url.split("://")[0]
    return sources

def prepare_payloads(self, payloads: list = []) -> tuple[list[str], int]:
    if self.args.wordlist:      # Load payloads from wordlist(s) and how many payloads will be tested.
        payloads = prepare_wordlist(self)
        keyspace = len(payloads) * len(self.args.extensions)
    elif self.args.backup_all:  # Prepare backup_all filenames to test.
        payloads = Backups(self).prepare_wordlist_for_backup_all()
        keyspace = len(payloads)
    elif self.args.archive:     # calculate keyspace from webarchive paths
        keyspace = len(payloads)
    elif self.args.bruteforce:  # Calculates how many payloads of brute-force combinations will be tested.
        keyspace = determine_keyspace(self.args)
    else:                     # When only --url is provided or when -src is provided
        if not self.args.source:  # when only --url is provided
            self.args.source = [self.target.url]
            self.target.url = self.target.domain_with_scheme
            keyspace = 0
        else:                     # when only -src is provided
            parsed = urllib.parse.urlparse(self.args.source[0])
            self.target.url = f"{parsed.scheme}://{parsed.netloc}"
            keyspace = 0
        self.target.path=""
        
    if self.args.source:        # Add sources provided by -src parameter
        self.args.source = get_unique_list(self.args.source)
        payloads += prepare_sources(self)
        keyspace += len(self.args.source) * len(self.args.extensions)

    if self.args.is_star_in_domain:
        payloads = remove_value_from_list(payloads, "")

    if self.args.parse_only:
        keyspace = 1

    return payloads, keyspace

def get_initial_directories(self) -> list[str]:
    if self.args.parse_only and self.target.path != "":  # If https://www.example.com/robots.txt is provided, no slash is added.
        response = self.scanner.send_request(self.target.url,redirects=False)
        if response.status_code == 200:
            return [self.target.path]
        else:
            return [self.target.path + "/"]
    else:
        return [self.target.path + "/"] if not self.args.is_star else [""]
    

def determine_keyspace(args: ArgumentOptions) -> int:
    if args.parse_only:
        return 1
    else:
        return ptcharsethelper.get_keyspace(args.charset, args.length_min, args.length_max, len(args.extensions))

def filter_urls_by_extension(urls: list[str], extensions_output: list[str]) -> list[str]:
    """Return only URLs whose file extension matches one in extensions_output."""
    extensions_output = [ext.lower().lstrip('.') for ext in extensions_output]  # normalize extensions
    filtered = []
    for url in urls:
        _, ext = os.path.splitext(url)
        if ext.lower().lstrip('.') in extensions_output:
            filtered.append(url)
    return filtered

def remove_value_from_list(items: list, value_to_remove) -> list:
    # Remove all occurrences of value_to_remove from items list and remove duplicates
    seen = set()
    result = []
    for item in items:
        if item == value_to_remove:
            continue
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result

def get_all_urls_from_response(response: requests.Response) -> list[str]:
    warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
    soup = BeautifulSoup(response.text, "html.parser")

    # Regex pattern to find URLs in robots.txt directives
    robots_pattern = re.compile(
        r'(?i)^(?:allow|disallow|sitemap):\s*(\S+)',
        re.MULTILINE
    )

    tags_with_href_or_src = [
        # href
        "a", "link", "area", "base",
        # src
        "img", "script", "iframe", "audio", "video", "source", "track", "embed", "input", "frame"
    ]

    excluded_schemes = (
        "blob:", "irc:", "mailto:", "tel:", "news:", "ftp:", "ftps:",
        "data:", "javascript:", "vbscript:",
        " ", "<", ">", "\\", "$", "%", "$", "'", "\""             # to avoid malformed URLs from backup files
    )

    ignored_values = ("", " ", ".", "/", "?", "#")

    urls = []

    urls_from_robots_txt = robots_pattern.findall(response.text)
    urls.extend(urls_from_robots_txt)

    for tag in soup.find_all(tags_with_href_or_src):
        for attr in ["href", "src"]:
            url = tag.get(attr)
            if not url or (url in ignored_values):
                continue

            url_lower = url.lower()
            if any(url_lower.startswith(s) for s in excluded_schemes):
                continue

            # convert relative URLs to absolute
            absolute_url = urllib.parse.urljoin(response.url, url)
            urls.append(absolute_url)
    return urls

def get_all_urls_from_mixed_url_list(parent, urls, domain, keep_params=False) -> tuple[list, list]:
    """
    Rozdělí URL podle domény.
    
    :param urls: list[str] - pole s URL nebo relativními cestami
    :param domain: str - doména, kterou považujeme za "naši"
    :param keep_params: bool - zda zachovat query a fragmenty
    :return: tuple(list, list) - (same_domain_paths, other_domain_urls)
    """
    same_domain_paths = set()
    other_domain_urls = set()

    for url in urls:
        if not url:
            continue

        parsed = urllib.parse.urlparse(url)

        # relative URL
        if not parsed.netloc:
            path = "/" + parsed.path if not parsed.path.startswith("/") else parsed.path
            url = parent.parent.target.domain_with_scheme + path
            if keep_params:
                url += ('?' + parsed.query) if parsed.query else ''
                url += ('#' + parsed.fragment) if parsed.fragment else ''
            same_domain_paths.add(url)
        else:  # absolute URL
            url = parent.parent.target.domain_with_scheme + parsed.path
            if keep_params:
                url += ('?' + parsed.query) if parsed.query else ''
                url += ('#' + parsed.fragment) if parsed.fragment else ''
            if parsed.netloc.lower().endswith(domain.lower()):
                # from our domain
                same_domain_paths.add(url)
            else:
                # foreign domain
                other_domain_urls.add(url)
    return list(same_domain_paths), list(other_domain_urls)

def normalize_urls(parent,urls):
    """Nahradí // na začátku URL za schema a odstraní duplicity."""
    normalized = []
    seen = set()

    for url in urls:
        # If URL starts with //, replace it with schema (e.g. "https:")
        if url.startswith("//"):
            url = parent.target.scheme + ":" + url

        # Add only if it hasn't been in the list yet
        if url not in seen:
            normalized.append(url)
            seen.add(url)

    return normalized


def normalize_url_paths(urls):
    """Odstraní ./ a ../ z cest v URL adresách."""
    normalized = []

    for url in urls:
        parsed = urllib.parse.urlparse(url)

        # clean the path (e.g. /a/b/../c → /a/c)
        clean_path = posixpath.normpath(parsed.path)

        # ensure that "/" at the end doesn't disappear if it was there
        if parsed.path.endswith("/") and not clean_path.endswith("/"):
            clean_path += "/"

        # reconstruct the URL
        cleaned_url = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            clean_path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))

        normalized.append(cleaned_url)

    return normalized

def normalize_url(url: str) -> str:
    """Normalizes the entire URL including scheme, domain, port, and path."""
    parsed = urllib.parse.urlparse(url)

    # Scheme and host are case-insensitive → convert to lowercase
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    # Split netloc into host, port
    hostname, sep, port = netloc.partition(":")

    # Remove default ports
    if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
        netloc = hostname
    elif port:
        netloc = f"{hostname}:{port}"
    else:
        netloc = hostname
    # Normalize path
    clean_path = posixpath.normpath(parsed.path)

    # ensure that "/" at the end doesn't disappear if it was there
    if parsed.path.endswith("/") and not clean_path.endswith("/"):
        clean_path += "/"

    # normpath returns "." if the path is empty → fix it
    if clean_path == ".":
        clean_path = ""

    # Reconstruct the URL
    normalized_url = urllib.parse.urlunparse((
        scheme,
        netloc,
        clean_path,
        parsed.params,
        parsed.query,
        parsed.fragment
    ))

    return normalized_url

def print_progress_line(self, url: str = None) -> None:
    dirs_todo = len(self.findings.get_notvisited_directories())
    dir_no = "(D:" + str(dirs_todo) + " / " + str(self.counters.get_progress_percentage()) + "%) " if dirs_todo else ""
    printed_line = f"{self.counters.get_time_to_finish()} ({str(self.counters.get_progress_complete_percentage())}%) {dir_no}{url}"

    self.printlock.lock_print(printed_line, end="\r", condition = not(self.args.json or self.args.silent), clear_to_eol=True)


def print_configuration(self) -> None:
    """
    Print the scan configuration and settings to the output.

    Args:
        args (ArgumentOptions): Parsed and processed command-line arguments.
    """
    ptprinthelper.ptprint( ptprinthelper.out_title_ifnot("Settings overview", self.args.json))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"URL................: {self.args.url}", "INFO", self.args.json))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Discovery-type.....: Brute force", "INFO", self.args.json or not self.args.bruteforce))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Discovery-type.....: Webarchive", "INFO", self.args.json or not self.args.archive))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Discovery-type.....: Complete backups only", "INFO", self.args.json or not self.args.backup_all))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Discovery-type.....: Dictionary", "INFO", self.args.json or not self.args.wordlist))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Discovery-type.....: Crawling", "INFO", self.args.json or not self.args.parse_only))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Discovery-type.....: Source check", "INFO", self.args.json or self.args.parse_only or self.args.wordlist or self.args.backup_all or self.args.bruteforce or self.args.archive or self.args.non_exist or self.args.extensions_whitelist))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Discovery-type.....: Extensions whitelisting check", "INFO", self.args.json or not self.args.extensions_whitelist))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Wordlist...........: {str(self.args.wordlist)}", "INFO", self.args.json or not self.args.wordlist))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Extensions.........: {self.args.extensions}", "INFO", self.args.json))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Method.............: {self.args.method}", "INFO", self.args.json))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"String starts......: {self.args.begin_with}", "INFO", self.args.json or not self.args.begin_with))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Is in response.....: {self.args.string_in_response}", "INFO", self.args.json or not self.args.string_in_response))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Is not in response.: {self.args.string_not_in_response}", "INFO", self.args.json or not self.args.string_not_in_response))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Charset............: {''.join(self.args.charset)}", "INFO", self.args.json or self.args.wordlist or self.args.parse_only))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Length-min.........: {self.args.length_min}", "INFO", self.args.json or self.args.parse_only))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Length-max.........: {self.args.length_max}", "INFO", self.args.json or self.args.parse_only))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Keyspace...........: {self.counters.keyspace}", "INFO", self.args.json or self.args.parse_only))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Delay..............: {self.args.delay}s", "INFO", self.args.json))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Threads............: {self.args.threads}", "INFO", self.args.json))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Recurse............: {self.args.recurse}", "INFO", self.args.json))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Parse content......: {self.args.parse}", "INFO", self.args.json))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Search for backups.: {self.args.backups}", "INFO", self.args.json))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Status code yes....: {self.args.status_code_yes}", "INFO", self.args.json))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Status code no.....: {self.args.status_code_no}", "INFO", self.args.json))
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f" ", "", self.args.json))