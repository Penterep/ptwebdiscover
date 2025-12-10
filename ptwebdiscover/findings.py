from ptlibs.threads.arraylock import ThreadSafeArray
from ptdataclasses.findingdetail import FindingDetail
from utils.url import Url
import helpers
import urllib


class Findings:
    findings = ThreadSafeArray[str]()                           # array of found URLs
    details = ThreadSafeArray[FindingDetail]()                  # array of finding details
    directories = ThreadSafeArray[str]()                        # array of discovered directories
    technologies = ThreadSafeArray[str]()                       # array of detected technologies
    visited = ThreadSafeArray[str]()                            # array of visited URLs. It is used in get_notvisited_urls() when Parse and Recursive options are enabled.
    visited_directories = ThreadSafeArray[str]()                # array of directories with ended dictionary or bruteforce searching
    parsed_urls = ThreadSafeArray[str]()                        # array of parsed URLs to avoid duplicates parsing
    long_content_in_redirect_urls = ThreadSafeArray[str]()      # array of URLs with long content in redirect
    directory_listing_urls = ThreadSafeArray[str]()             # array of URLs with directory listing
    backups_urls = ThreadSafeArray[str]()                       # array of found backup URLs
    foreign_domain_urls = ThreadSafeArray[str]()                # array of URLs pointing to foreign domains
    forbidden_paths = ThreadSafeArray[str]()                    # array of paths that should not be tested
    insecure_resources = ThreadSafeArray[dict[str, list[str]]]()# array of insecure resources [{"url":["resource1", "resource2"]}]
    fpd = ThreadSafeArray[dict[str, list[str]]]()               # array of full path disclosure [{"url":["fpd1", "fpd2"]}]
    findings_from_wordlist = ThreadSafeArray[str]()             # array of findings discovered from wordlist

    def __init__(self) -> None:
        pass

    def get_notvisited_directories(self) -> list[str]:
        """
        Get a list of directories that have been discovered but not yet visited.

        Returns:
            list[str]: A list of unvisited directories.
        """
        not_visited_directories = []
        for directory in self.directories:
            if directory not in self.visited_directories:
                not_visited_directories.append(directory)
        return not_visited_directories
    
    def add_to_findings(self, url: str) -> None:
        url_encode = helpers.encode_url_path(url)
        url_decode = urllib.parse.unquote(url)
        if url not in self.findings and url_encode not in self.findings and url_decode not in self.findings:
            self.findings.append(url)
    
    def add_to_directory_listing_urls(self, url: str) -> None:
        if url not in self.directory_listing_urls:
            self.directory_listing_urls.append(url)

    def add_to_long_content_in_redirect_urls(self, url: str) -> None:
        if url not in self.long_content_in_redirect_urls:
            self.long_content_in_redirect_urls.append(url)

    def add_to_backups_urls(self, url: str) -> None:
        if url not in self.backups_urls:
            self.backups_urls.append(url)
    
    def add_to_findings_from_wordlist(self, url: str) -> None:
        if url not in self.findings_from_wordlist:
            self.findings_from_wordlist.append(url)

    def add_to_foreign_domain_urls(self, urls: list[str]) -> None:
        for url in urls:
            if url not in self.foreign_domain_urls:
                self.foreign_domain_urls.append(url)

    def is_url_forbidden(self, url: str) -> bool:
        """
        Check if a given URL contains any forbidden paths.

        Parameters:
            url (str): The URL to check.

        Returns:
            bool: True if the URL is forbidden, False otherwise.
        """
        url_path = Url(url).get_path_from_url()
        for forbidden_path in self.forbidden_paths:
            # Check if the url_path starts with the forbidden_path
            if url_path.startswith(forbidden_path):
                return True
        return False
    
    def add_insecure_resources(self, page_url: str, resources: list[str]) -> None:
        if not resources:
            return

        # Zkontrolovat, jestli URL už existuje
        for entry in self.insecure_resources:
            if page_url in entry:
                return  # URL už je přítomna, nic nepřidávat

        # Přidat novou URL a její zdroje
        self.insecure_resources.append({page_url: resources})
    
    def add_fpd(self, url_fpd:list[dict[str, list[str]]]) -> None:
        existing_keys = {key for d in self.fpd for key in d}
        for d in url_fpd:
            key = next(iter(d))
            if key not in existing_keys:
                self.fpd.extend(url_fpd)

