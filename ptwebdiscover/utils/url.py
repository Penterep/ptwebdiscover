import os
import urllib.parse
from ptlibs import tldparser

class Url:
    """
    A utility class for representing and manipulating URLs.

    This class provides helper methods for extracting paths, domains, and
    schemes from URLs, removing parameters, and ensuring standardized formats.
    It is designed to handle common URL transformations and parsing logic.

    Attributes:
        url (str): The original URL string.
    """

    def __init__(self, url: str) -> None:
        """
        Initialize a Url object.

        Args:
            url (str): The URL string to be stored and manipulated.
        """
        self.url = url

    def get_path_from_url(self, with_l_slash: bool = True, without_r_slash: bool = False) -> str:
        """
        Extract the path component from the URL.

        Args:
            with_l_slash (bool): If True, the returned path starts with '/'.
            without_r_slash (bool): If True and the URL is a directory (ends with '/'),
                the trailing slash will be removed.

        Returns:
            str: The path portion of the URL based on the given options.
        """
        url = self.get_url_without_parameters()
        out_r_slash = -1 if self.is_url_directory() and without_r_slash else None
        url = url.replace("//", "::")
        domain_len = url.find("/") if url.find("/")>0 else len(url)
        if with_l_slash:
            return url[domain_len:out_r_slash]
        else:
            return url[domain_len+1:out_r_slash]
        
    def get_port_from_url(self) -> str:
        """
        Extract the port from the URL, if specified.

        Returns:
            str: The port number as a string, or an empty string if not specified.
        """
        extract = urllib.parse.urlparse(self.url)
        return str(extract.port) if extract.port else (443 if self.get_scheme_from_url() == "https" else 80)
    
    def get_scheme_from_url(self) -> str:
        """
        Extract the scheme (protocol) from the URL.

        Returns:
            str: The scheme of the URL (e.g., 'http', 'https').
        """
        extract = urllib.parse.urlparse(self.url)
        return extract.scheme if extract.scheme else "http"

    def get_url_without_parameters(self) -> str:
        """
        Return the URL without query parameters or fragments.

        Returns:
            str: The URL without '?' query parameters and '#' fragments.
        """
        return self.url.split("?")[0].split("#")[0]

    def is_url_directory(self) -> bool:
        """
        Check if the URL points to a directory.

        Returns:
            bool: True if the URL ends with '/', otherwise False.
        """
        return self.get_url_without_parameters().endswith("/")

    def standardize_url(self, domain_with_scheme: str) -> str:
        """
        Convert the stored URL to an absolute path form with a given domain.

        Args:
            domain_with_scheme (str): The full domain including the scheme
                (e.g., 'https://example.com').

        Returns:
            str: The standardized absolute URL.
        """
        path = self.url[len(domain_with_scheme):]
        if not path.startswith("/"):
            path = "/"
        abs = os.path.abspath(path)+"/" if path.endswith("/") and path !="/" else os.path.abspath(path)
        return domain_with_scheme + abs
    

    def get_domain_from_url(self, level: bool = True, with_protocol: bool = True, with_port: bool = True) -> str:
        """
        Extract domain from URL, optionally including subdomains, scheme and port.
        """
        parsed = urllib.parse.urlparse(self.url)

        # tldextract pracuje pouze s hostname
        extract = tldparser.parse(self.url)

        # složení hostname části
        if level and extract.subdomain:
            host = f"{extract.subdomain}.{extract.domain}"
        else:
            host = extract.domain

        if extract.suffix:
            host = f"{host}.{extract.suffix}"

        # protokol
        protocol = f"{parsed.scheme}://" if with_protocol and parsed.scheme else ""

        # port
        port = f":{parsed.port}" if with_port and parsed.port else ""

        return f"{protocol}{host}{port}"

    def add_missing_scheme(self, scheme: str) -> str:
        """
        Ensure the URL has a scheme. If missing, prepend the given scheme.

        Args:
            scheme (str): The scheme to prepend (e.g., 'http', 'https').

        Returns:
            str: The URL with a scheme.
        """
        extract = urllib.parse.urlparse(self.url)
        if self.url and not (extract.scheme):
            return scheme + "://" + self.url
        else:
            return self.url