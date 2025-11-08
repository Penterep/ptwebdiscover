import time
import copy
import requests
import helpers
import urllib.parse
from utils.url import Url
from ptlibs import ptprinthelper, ptmisclib
from responseprocessor import ResponseProcessor
from ptlibs import ptcharsethelper

class Scanner:
    def __init__(self, parent) -> None:
        self.parent = parent


    def main_searching(self, directories: list[str], payloads: list[str]) -> None:
        for directory in directories:
            if directory in self.parent.findings.visited_directories:
                continue
            self.parent.counters.reset_counter()
            self.parent.counters.set_actual_directory(directory)
            self.parent.counters.increment_directory_finished()
            self.parent.findings.visited_directories.append(directory)

            self.process_directory(copy.deepcopy(payloads))

        self.parent.findings.directories = self.parent.findings.get_notvisited_directories()
        self.parent.counters.reset_directory_finished()
            


    def process_directory(self, payloads=[]) -> None:
        """
        Process a single directory by performing discovery using brute force or wordlists.

        Args:
            args (ArgumentOptions): Parsed and processed command-line arguments.
        """
        if not self.parent.args.is_star_in_domain:
            # Check status for non-existing resource in the current directory and add it to --status-code-no
            domain_with_path = self.parent.target.domain_with_scheme + self.parent.counters.get_actual_directory(add_slash_to_end=False)
            status_code = self.get_status_for_non_existing_resource(domain_with_path)
            if not self.parent.args.string_not_in_response and not self.parent.args.string_in_response:
                self.parent.counters.set_actual_directory_not_found_status(status_code)
            ptprinthelper.clear_line_ifnot(condition = self.parent.args.json)
            ptprinthelper.ptprint( ptprinthelper.out_title_ifnot(f"Check {domain_with_path}", self.parent.args.json))
            ptprinthelper.ptprint( ptprinthelper.out_title_ifnot(f"Not found status code: {status_code}", self.parent.args.json))
        # Dictionary-based discovery
        if not self.parent.args.bruteforce:
            self.parent.ptthreads.threads(payloads, self.dictionary_discover, self.parent.args.threads)
        # Bruteforce
        else:
            combinations = ptcharsethelper.get_combinations(self.parent.args.charset, self.parent.args.length_min, self.parent.args.length_max)
            self.parent.ptthreads.threads(combinations, self.bruteforce_discover, self.parent.args.threads)


    def dictionary_discover(self, line: str) -> None:
        """
        Perform dictionary-based discovery using the provided wordlist entry.
        RUN IN THREADS
        
        Args:
            line (str): A single entry from the wordlist (optionally with technology info).
        """
        for extension in self.parent.args.extensions:
            self.parent.counters.increment_counter()
            self.parent.counters.increment_counter_complete()
            split_line = line.split("::")   # split source from special technology wodrlist
            source = self.parent.args.prefix + split_line[0] + self.parent.args.suffix

            try:
                technology = split_line[1]
            except:
                technology = None

            if self.parent.args.is_star:
                request_url = self.parent.target.url[:self.parent.args.position] + self.parent.counters.get_actual_directory() + source + extension + self.parent.target.url[self.parent.args.position:]
            else:
                request_url = self.parent.target.domain_with_scheme + self.parent.counters.get_actual_directory() + source + extension

            if not (extension != "" and (source == "" or source.endswith("/"))):
                response = self.prepare_and_send_request(request_url)
            
            if response.status_code:
                self.process_response(request_url, response, source, technology)


    def bruteforce_discover(self, combination: str) -> None:
        """
        Perform brute force discovery using a generated character combination.
        RUN IN THREADS

        Args:
            combination (str): A string combination from the charset keyspace.
        """
        if not self.parent.args.case_insensitive and "capitalize" in self.parent.args.charsets:
            combination = combination.capitalize()
        for extension in self.parent.args.extensions:
            self.parent.counters.increment_counter()
            self.parent.counters.increment_counter_complete()

            if self.parent.args.is_star:
                request_url = self.parent.target.url[:self.parent.args.position] + self.parent.counters.actual_directory + self.parent.args.prefix + ''.join(combination) + self.parent.args.suffix + extension + self.parent.target.url[self.parent.args.position:]
            else:
                request_url = self.parent.target.domain_with_scheme + self.parent.counters.actual_directory + self.parent.args.prefix + ''.join(combination) + self.parent.args.suffix + extension
            
            response = self.prepare_and_send_request(request_url)
            if response.status_code:
                self.process_response(request_url, response, ''.join(combination))

    def process_notvisited_urls(self) -> None:
        """
        Process all URLs that have been discovered but not yet visited.

        In parse mode, this continues recursively discovering new URLs.
        """

        #TODO Run brute force or directory for every new directory
        ptprinthelper.clear_line_ifnot(condition = self.parent.args.json)
        ptprinthelper.ptprint( ptprinthelper.out_title_ifnot("Checking not visited sources", self.parent.args.json))
        while True:
            not_visited_urls = self.get_notvisited_urls()
            keyspace = len(not_visited_urls) + ((len(self.parent.findings.get_notvisited_directories()) * self.parent.counters.get_keyspace()) if self.parent.args.recurse else 0)
            self.parent.counters.reset_counter_complete()
            self.parent.counters.set_keyspace_complete(keyspace)
            if not not_visited_urls:
                break
            self.parent.ptthreads.threads(not_visited_urls, self.process_notvisited, self.parent.args.threads)


    def get_notvisited_urls(self) -> list[str]:
        """
        Get a list of URLs that have been discovered but not yet visited.
        RUN IN THREADS
        
        Returns:
            list[str]: A list of unvisited URLs.
        """
        self.parent.counters.increment_counter_complete()
        not_visited_urls = []
        for url in self.parent.findings.findings:
            if url not in self.parent.findings.visited and url[:-1] not in self.parent.findings.visited:
                not_visited_urls.append(url)
        return not_visited_urls


    def process_notvisited(self, url: str) -> None:
        """
        Visit and process a single unvisited URL.
        RUN IN THREADS

        Args:
            url (str): The URL to visit and process.
        """
        response = self.prepare_and_send_request(url)
        
        self.add_all_urls_from_request_history_to_visited(response)
        
        if response.status_code:
                self.process_response(url, response)
        


    def prepare_and_send_request(self, url: str) -> None:
        """
        Prepare and send a request to a target URL, then process the response.

        Args:
            url (str): The full request URL.
            combination (str): The tested string combination or wordlist entry.
            technology (str, optional): Technology tag associated with the request.

        Returns:
            bool: True if the response status code is 200, False otherwise.
        """
        try:
            response = self.send_request(url)
            self.add_all_urls_from_request_history_to_visited(response)
        except Exception as e:
            if not self.parent.args.is_star_in_domain:
                if self.parent.args.errors:
                    self.parent.printlock.lock_print( ptprinthelper.out_ifnot(url + " : " + str(e), "ERROR", self.parent.args.json), clear_to_eol=True)
                raise e

        # Print progress line    
        helpers.print_progress_line(self.parent, url)
        time.sleep(self.parent.args.delay)

        return response


    def send_request(self, url: str, redirects=None, method=None, headers=None, timeout=None, verify=False, auth=None, cache=None, proxies=None, max_retries=2) -> requests.Response:
        """
        Send an HTTP request with configured method, headers, and proxy.

        Args:
            url (str): The target URL.

        Returns:
            requests.Response: The HTTP response.
        """
        if self.parent.findings.is_url_forbidden(url):
            return None
        redirects = not(self.parent.args.not_redirect) if redirects is None else redirects
        method = self.parent.args.method if method is None else method
        proxies = self.parent.args.proxies if proxies is None else proxies
        headers = self.parent.args.headers if headers is None else headers
        timeout = self.parent.args.timeout if timeout is None else timeout
        auth = self.parent.args.auth if auth is None else auth
        cache = self.parent.args.cache if cache is None else cache
        headers = copy.deepcopy(self.parent.args.headers)
        
        if self.parent.args.target_server:
            host = urllib.parse.urlparse(url).netloc
            url = self.parent.args.target_server
            headers.update({'Host': host})
        
        response = ptmisclib.load_url_from_web_or_temp(url, method, headers=headers, timeout=self.parent.args.timeout, proxies=self.parent.args.proxies, verify=verify, redirects=redirects, auth=auth, cache=cache, max_retries=max_retries)
        
        # If redirect detected on HEAD request, resend as GET for check length of content in get_response_history()
        if response.history and method.upper() == "HEAD":
            response = ptmisclib.load_url_from_web_or_temp(url, "GET", headers=headers, timeout=self.parent.args.timeout, proxies=self.parent.args.proxies, verify=verify, redirects=redirects, auth=auth, cache=cache, max_retries=max_retries)
        return response


    def is_response_compliant(self, response: requests.Response, request_url: str = None) -> bool:
        """
        Determine if the response is compliant with the defined criteria.

        Args:
            response (requests.Response): The HTTP response.

        Returns:
            bool: True if compliant, False otherwise.
        """
        has_redirect = len(response.history) > 0

        status_differs = (
            self.parent.counters.non_existing_domain_status
            and response.status_code != self.parent.counters.non_existing_domain_status
        )

        title_differs = (
            self.parent.counters.non_existing_domain_title
            and self.parent.counters.non_existing_domain_title not in response.text
        )

        redirect_differs = (
            self.parent.counters.non_existing_domain_redirect is not None
            and has_redirect != self.parent.counters.non_existing_domain_redirect
        )
        if self.parent.args.not_redirect and "Location" in response.headers:
            response_domain = Url(response.headers["Location"]).get_domain_from_url(level=True, with_protocol=False)
        elif self.parent.args.target_server:
            response_domain = Url(request_url).get_domain_from_url(level=True, with_protocol=False) 
        else:
            response_domain = Url(response.url).get_domain_from_url(level=True, with_protocol=False)

        return (
            (
                # domain must match
                response_domain == Url(request_url).get_domain_from_url(level=True, with_protocol=False) 
                # status_code must be allowed (if list is not empty)
                and (not self.parent.args.status_code_yes or response.status_code in self.parent.args.status_code_yes)
                # status_code must not be denied
                and response.status_code not in self.parent.args.status_code_no
                and (response.status_code != self.parent.counters.get_actual_directory_not_found_status() or self.parent.args.parse_only)
                # compare status_code, redirect and title when star in domain
                and (not self.parent.args.is_star_in_domain or (status_differs or title_differs or redirect_differs))
            )
            # string must exist
            and (not self.parent.args.string_in_response or self.parent.args.string_in_response in response.text)
            # string must not exist
            and (not self.parent.args.string_not_in_response or self.parent.args.string_not_in_response not in response.text)
        )

    def process_response(self, request_url: str, response: requests.Response, source: str=None, technology:str = None) -> None:
        """
        Process an HTTP response, extract information, and record findings.

        Args:
            request_url (str): The request URL.
            response (requests.Response): The HTTP response object.
            combination (str): The tested string or combination.
            technology (str, optional): Technology tag if known.
        """
        if self.is_response_compliant(response, request_url):
            response_processor = ResponseProcessor(self.parent)

            if self.parent.args.save and response_processor.content_shorter_than_maximum(response):
                path = Url(request_url).get_path_from_url(with_l_slash=False)
                response_processor.save_content(response.content, path, self.parent.args.save)

            content_type, ct_bullet = response_processor.get_text_directory_or_file(response, request_url)
            history = response_processor.get_response_history(response.history)
            content_location = response_processor.get_content_location(response)
            
            if self.parent.args.parse:
                parsed_urls = response_processor.parse_html_find_and_add_urls(response)
            else:
                parsed_urls = ""
            
            c_t, c_l = response_processor.get_content_type_and_length(response.headers)
            c_t_l = " [" + c_t + ", " + c_l + "b] "
            show_target = source if self.parent.args.target_server else response.url
            
            # Print finding
            if not self.parent.args.json:
                if parsed_urls and content_location:
                    parsed_urls = parsed_urls + "\n"

                self.parent.printlock.lock_print(
                    history +
                    ptprinthelper.add_spaces_to_eon(
                    ptprinthelper.out_ifnot(f"[{response.status_code}] {ct_bullet} {show_target}", "OK", self.parent.args.json) + " " +
                    ptprinthelper.out_ifnot(f"{technology}", "INFO", self.parent.args.json or not technology), len(c_t_l), condition=self.parent.args.json) +
                    ptprinthelper.out_ifnot(c_t_l, "", self.parent.args.json) + parsed_urls + content_location, clear_to_eol=True)

                helpers.print_progress_line(self.parent, url=request_url) # Print progress line after finding

            response_processor.parse_url_and_add_unique_url_and_directories(response.url, response)

            if technology:
                response_processor.add_unique_technology_to_technologies(technology)

        # Remove URL found in html but not compliant
        elif response.url in self.parent.findings:
            self.parent.findings.remove(response.url)

    def add_all_urls_from_request_history_to_visited(self, response: requests.Response) -> None:
        """
        Add all URLs from the request history to the visited list.

        Args:
            response (requests.Response): The HTTP response object.
        """
        for resp in response.history:
            if resp.url not in self.parent.findings.visited:
                self.parent.findings.visited.append(resp.url)
        if response.url not in self.parent.findings.visited:
            self.parent.findings.visited.append(response.url)

    def test_status_for_non_existing_resource(self,url:str) -> None:
        ptprinthelper.ptprint("Check status for not-existing resource", "TITLE", condition=not self.parent.args.json, colortext=True)
        status_code = self.get_status_for_non_existing_resource(url)
        if status_code == 200:
            self.parent.ptjsonlib.add_vulnerability("PTV-WEB-INJECT-REFLEXURL")
            self.parent.ptjsonlib.end_ok("Server returned status code 200 for not-existing resources", self.parent.args.json, bullet_type="VULN")
        else:
            self.parent.ptjsonlib.end_ok(f"Server returned status code {status_code} for non existing resource", self.parent.args.json, bullet_type="OK")


    def get_status_for_non_existing_resource(self, url: str) -> int:
        url = url + "/" if not url.endswith("/") else url
        url = url + "this-resource-does-not-exist"
        response = self.send_request(url)
        return response.status_code


    def _change_schema_when_redirect_from_http_to_https(self, response: requests.Response, old_extract: urllib.parse.ParseResult) -> tuple[str,int]:
        """
        Adjust URL schema if redirected from HTTP to HTTPS.

        Args:
            response (requests.Response): The redirect response.
            old_extract (urllib.parse.ParseResult): Parsed original URL.

        Returns:
            tuple[str, int]: Updated URL and position index.
        """
        target_location = response.headers["Location"]
        new_extract = urllib.parse.urlparse(target_location)
        if old_extract.scheme == "http" and new_extract.scheme == "https" and old_extract.netloc == new_extract.netloc:
            ptprinthelper.ptprint("Redirect from http to https detected, changing default scheme to https", "INFO", not self.args.json)
            self.target.url  = self.target.url.replace("http", "https", 1)
            self.domain_with_scheme = self.domain_with_scheme.replace("http://", "https://", 1)
            self.domain_protocol = "https"
            self.args.position += 1
        else:
            ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Returned status code {response.status_code}. Site redirected to {target_location}. Check target in -u option.\n", "ERROR", self.args.json), end="\n", clear_to_eol=True)
        return (self.target.url, self.args.position)

    def check_extensions_whitelisting(self) -> None:
        """
        Check if the server is whitelisting certain file extensions.

        This method tests a set of common backup and configuration file extensions
        to determine if the server allows access to them, indicating potential
        security misconfigurations.
        """
        test_directory = self.parent.counters.get_actual_directory()
        test_schema_path = self.parent.target.domain_with_scheme + test_directory
        test_url_file = test_schema_path + "/nonexistfile"
        non_exist_status_code = self.get_status_for_non_existing_resource(test_url_file + ".jpg")
        ptprinthelper.ptprint("Checking for extensions whitelisting", "TITLE", condition=not self.parent.args.json, colortext=True)
        
        for extension in self.parent.args.extensions_whitelist:
            if not extension.startswith("."):
                extension = ".jpg" + extension
            self.check_extension_whitelisteing(test_url_file + extension, extension, non_exist_status_code)

        self.check_dotfile_whitelisteing(test_schema_path, non_exist_status_code)


    def check_extension_whitelisteing(self, url: str, extension: str = None, non_exist_status_code: int = 404) -> None:
        response = self.send_request(url)
        if response.status_code != non_exist_status_code:
            ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Extension {extension:<5} returned status code {response.status_code}", "OK", self.parent.args.json), end="\n", clear_to_eol=True)
            #self.parent.ptjsonlib.add_vulnerability(f"PTV-WEB-EXT-WHITELIST-{extension.upper().replace('.', '')}")
        else:
            ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Extension {extension:<5} returned the same status code ({response.status_code}) as the non-existing resource", "ERROR", self.parent.args.json), end="\n", clear_to_eol=True)


    def check_dotfile_whitelisteing(self, test_schema_path: str, non_exist_status_code: int = 404) -> None:
        url = test_schema_path + "/.dot"
        response = self.send_request(url)
        if response.status_code != non_exist_status_code:
            ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Filename started with '.' returned status code {response.status_code}", "OK", self.parent.args.json), end="\n", clear_to_eol=True)
            #self.parent.ptjsonlib.add_vulnerability(f"PTV-WEB-EXT-WHITELIST-{extension.upper().replace('.', '')}")
        else:
            ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Filename started with '.' returned the same status code ({response.status_code}) as the non-existing resource", "ERROR", self.parent.args.json), end="\n", clear_to_eol=True)