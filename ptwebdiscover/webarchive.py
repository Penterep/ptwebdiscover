from ptlibs import ptprinthelper
from ptlibs.http.http_client import HttpClient

import urllib.parse

def get_urls_from_webarchive(self) -> None:
    http_client = HttpClient(args=self.args, ptjsonlib=self.ptjsonlib)

    ptprinthelper.ptprint("WebArchive.org crawling:", "TITLE", condition=not self.args.json, clear_to_eol=True)

    API_URL = f"https://web.archive.org/cdx/search/cdx?url={urllib.parse.urlparse(self.target.url).netloc}/*&fl=original&output=txt&collapse=urlkey&filter=!statuscode:404"
    response = http_client.send_request(url=API_URL, method="GET", allow_redirects=False, timeout=300)
    url_list = parse_response(self, response)
    path_list = list(set(url.split("/", 3)[-1] for url in url_list))

    return url_list, path_list

def parse_response(self, response):
    results = set()
    parsed_url = urllib.parse.urlparse(self.target.url)
    for line in response.text.split():
        result = replace_url_parts_in_line(self.args, line, scheme=parsed_url.scheme, netloc=parsed_url.netloc)
        results.add(result)

    return list(results)


def replace_url_parts_in_line(args, line, scheme=None, netloc=None, path=None, query=None):
    """
    Parse a URL from a line of text, replace specified parts, and return the rebuilt URL.

    Parameters:
        line (str): The line containing the URL.
        scheme (str, optional): New scheme (e.g., 'https').
        netloc (str, optional): New network location (domain + port).
        path (str, optional): New path.
        query (str, optional): New query string.

    Returns:
        str: Rebuilt URL with updated parts.
    """
    # Parse the URL from the line
    parsed = urllib.parse.urlparse(line)
    # Replace parts if provided, otherwise keep original
    new_scheme = scheme if scheme is not None else parsed.scheme
    new_netloc = netloc if netloc is not None else parsed.netloc
    new_path = path if path is not None else parsed.path
    new_query = query if query is not None else parsed.query

    if not args.include_parameters:
        new_query = None

    # Rebuild the URL
    new_url = urllib.parse.urlunparse((
        new_scheme,
        new_netloc,
        new_path,
        parsed.params,
        new_query,
        parsed.fragment
    ))

    return new_url