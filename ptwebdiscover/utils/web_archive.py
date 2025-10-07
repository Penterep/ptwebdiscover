import os
import tempfile

from findings import Findings

import ptlibs.ptprinthelper as ptprinthelper
from ptlibs.http.http_client import HttpClient

import urllib.parse

class WebArchiveCrawler:
    def __init__(self, args, ptjsonlib):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.no_params = "noparams" in str(args.archive)
        self.check = "checked" in str(args.archive)
        self.http_client = HttpClient(args=self.args, ptjsonlib=self.ptjsonlib)

        self.wordlist_path = None

    def run(self, url):
        """Run scan"""
        ptprinthelper.ptprint("WebArchive.org crawling:", "TITLE", condition=not self.args.json, clear_to_eol=True)

        self.parsed_original_url = urllib.parse.urlparse(self.args.url)
        API_URL = f"https://web.archive.org/cdx/search/cdx?url={urllib.parse.urlparse(url).netloc}/*&fl=original&output=txt&collapse=urlkey&filter=!statuscode:404"
        response = self.http_client.send_request(url=API_URL, method="GET", headers=self.args.headers, allow_redirects=False, timeout=300)
        url_list = self.parse_response(response)

        if self.check:
            path_list = list(set(url.split("/", 3)[-1] for url in url_list))
            self.wordlist_path = self.create_tmp_file(path_list) # create wordlist

        return url_list

    def parse_response(self, response):
        results = set()
        for line in response.text.split():
            result = self.replace_url_parts_in_line(line, scheme=self.parsed_original_url.scheme, netloc=self.parsed_original_url.netloc)
            results.add(result)

        return list(results)


    def replace_url_parts_in_line(self, line, scheme=None, netloc=None, path=None, query=None):
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

        if self.no_params:
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


    def create_tmp_file(self, content: list[str]) -> str:
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(content))
        return path