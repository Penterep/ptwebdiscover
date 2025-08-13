#!/usr/bin/python3
"""
    Copyright (c) 2024 Penterep Security s.r.o.

    ptwebdiscover - Web Source Discovery Tool

    ptwebdiscover is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ptwebdiscover is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ptwebdiscover.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import datetime
import time
import sys; sys.path.append(__file__.rsplit("/", 1)[0])
import urllib.parse
import re
import glob
import copy
import requests
from urllib.parse import urlparse

from io import TextIOWrapper

from ptlibs import ptnethelper, ptcharsethelper, ptprinthelper, ptjsonlib, ptmisclib
from ptlibs.threads import ptthreads, printlock, arraylock

from ptdataclasses.argumentoptions import ArgumentOptions
from ptdataclasses.processedargumentoptions import ProcessedArgumentOptions
from ptdataclasses.findingdetail import FindingDetail

from utils import treeshow
from utils.url import Url

from responseprocessing import ResponseProcessor
from findings import Findings
from keyspace import Keyspace

from _version import __version__

class PtWebDiscover():
    def __init__(self, args: ArgumentOptions) -> None:
        """
        Initialize the PtWebDiscover instance with configuration, locks, and derived arguments.

        This method processes the provided arguments to set up the scanning environment,
        normalizes URLs, prepares headers, proxies, character sets, and extensions, and
        validates incompatible argument combinations.

        Args:
            args (ArgumentOptions): Parsed and processed command-line arguments.
        """
        self.ptjsonlib                       = ptjsonlib.PtJsonLib()
        self.ptthreads                       = ptthreads.PtThreads()
        self.printlock                       = printlock.PrintLock()
        self.arraylock                       = arraylock.ArrayLock()
        self.use_json                        = args.json
        self.args: ProcessedArgumentOptions  = args
        self.args.is_star: bool              = True if "*" in args.url else False
        self.args.timeout: int               = args.timeout / 1000
        self.args.content_length: int        = args.content_length * 1000
        self.args.delay: int                 = args.delay / 1000
        self.args.nochanged_url: str         = self.args.url
        self.args.url                        = ptnethelper.remove_slash_from_end_url(args.url) if not self.args.is_star else args.url
        self.args.url                        = Url(args.url).add_missing_scheme(self.args.scheme)
        self.args.target: str                = Url(args.target).add_missing_scheme(self.args.scheme)
        self.args.position, self.args.url    = self.get_star_position(self.args.url)
        self.args.proxies: dict              = {"http": args.proxy, "https": args.proxy}
        self.args.headers: dict              = ptnethelper.get_request_headers(args)
        self.args.charset: list              = ptcharsethelper.get_charset(["lowercase"]) if not args.charsets and not args.wordlist else ptcharsethelper.get_charset(args.charsets)
        self.args.parse: bool                = args.parse or args.parse_only
        self.args.length_max: int            = args.length_max if args.length_max else 99 if args.wordlist else 6
        self.args.begin_with: str            = args.begin_with if args.begin_with else ""
        self.args.threads: int               = args.threads if not args.delay  else 1
        self.args.method: str                = args.method if not (args.string_in_response or args.string_not_in_response or args.parse or args.save) else "GET"
        self.domain                          = Url(self.args.url).get_domain_from_url(level=True, with_protocol=False)
        self.domain_with_protocol            = Url(self.args.url).get_domain_from_url(level=True, with_protocol=True)
        self.domain_protocol                 = urllib.parse.urlparse(args.url).scheme
        self.args.is_star_in_domain          = True if self.args.is_star and self.args.position < len(self.domain_with_protocol)+1 else False
        self.urlpath                         = Url(self.args.url).get_path_from_url(with_l_slash=True, without_r_slash=True)
        self.args.auth                       = tuple(args.auth.split(":")) if args.auth else None

        self.args.extensions                 = self.prepare_extensions(args) # must be placed after set of self.directories
        Findings.directories                 = arraylock.ThreadSafeArray([self.urlpath + "/"] if not self.args.is_star else [""])
        #self.ptthreads                      = ptthreads.PtThreads(args.errors)
        self.check_args_combinations()
        self.prepare_not_directories(self.args.not_directories)

        if args.non_exist and self.args.is_star:
            ptprinthelper.ptprint(" ", None)
            self.ptjsonlib.end_error("Cannot use anchor '*' with -ne/--non-exist options", self.use_json)

    def run(self, args: ArgumentOptions) -> None:
        """
        Execute the web discovery process.

        This is the main entry point for running the scan. It handles DNS caching,
        cookie initialization, keyspace calculation, directory scanning, recursion,
        backup searching, and final result reporting.

        Args:
            args (ArgumentOptions): Parsed and processed command-line arguments.
        """

        if not args.without_dns_cache:
            self.cache_dns()

        if not self.args.is_star_in_domain:
            # TODO set cookies with star in url too
            self.set_header_cookies()

        self.initialize_counters()    #  Prepares timing and progress tracking.
        self.determine_keyspace(args) # Calculates how many payloads (wordlist entries or brute-force combinations) will be tested.
        self.print_configuration(args) # Outputs the current settings so the user can see what will be tested.
        self.determine_keyspace_complete(args.parse_only) # Finalizes the keyspace count, or sets it to 1 in parse-only mode.

        if args.non_exist: # send request to non existing source
            self.check_status_for_non_existing_resource(args)

        for self.directory_finished, self.directory in enumerate(Findings.directories):
            self.process_directory(args)

        if self.args.recurse:
            self.process_notvisited_urls()

        if self.args.backups:
            self.process_backups()

        if self.args.backups or self.args.backups_only:
            self.process_all_backups()

        self.print_results()

    def check_status_for_non_existing_resource(self, args):
        """
        Send request to non-existing resource on target server, if server returns status 200, PTV-WEB-INJECT-REFLEXURL will be added to vulnerabilities

        Test server behavior for a non-existing resource.

        Sends a request to a deliberately non-existent file and checks the response
        status code. If the server incorrectly returns 200 OK, a vulnerability flag
        is recorded.

        Args:
            args (ArgumentOptions): Parsed and processed command-line arguments.
        """
        ptprinthelper.ptprint("Check status for not-existing resource", "TITLE", condition=not self.use_json, colortext=True)

        url = args.url + "/d8d9afas7d49f6a1dsf.php"
        ptprinthelper.ptprint(f"Sending request to: {url}", "INFO", condition=not self.use_json)
        response = self.send_request(url)

        ptprinthelper.ptprint(f"Returned status code: {response.status_code}", "INFO", condition=not self.use_json)

        if response.status_code == 200:# in [200, ]:
            self.ptjsonlib.add_vulnerability("PTV-WEB-INJECT-REFLEXURL") # TODO: Really a vuln?
            ptprinthelper.ptprint("Server returned SC 200 for not-existing resources", bullet_type="VULN", condition=True)


    def cache_dns(self) -> None:
        """
        Cache DNS lookups for improved performance.

        This function imports and initializes DNS cache handling utilities.
        """
        from utils import cachefile


    def set_header_cookies(self):
        """
        Set the 'Cookie' header in the request headers.

        Performs an availability check on the target URL and extracts cookies from
        the server response, adding them to the request headers for subsequent requests.
        """
        response = self.check_url_availability(self.args.url, self.args.proxies, self.args.headers, self.args.auth, self.args.method, self.args.position)
        self.args.headers["Cookie"] = self.get_and_set_cookies(response)


    def initialize_counters(self):
        self.start_time = time.time()
        self.counter_complete = 0


    def determine_keyspace(self, args: ArgumentOptions) -> None:
        """
        Determine the total keyspace of possible payloads to test.

        If a wordlist is provided, the keyspace is derived from it. Otherwise, it is
        generated from the provided charset, length constraints, and file extensions.

        Args:
            args (ArgumentOptions): Parsed and processed command-line arguments.
        """
        if args.wordlist:
            Keyspace.space, _ = self.try_prepare_wordlist(args)
        else:
            Keyspace.space = ptcharsethelper.get_keyspace(self.args.charset, self.args.length_min, self.args.length_max, len(self.args.extensions))


    def print_configuration(self, args: ArgumentOptions) -> None:
        """
        Print the scan configuration and settings to the output.

        Args:
            args (ArgumentOptions): Parsed and processed command-line arguments.
        """
        ptprinthelper.ptprint( ptprinthelper.out_title_ifnot("Settings overview", self.args.json))
        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"URL................: {self.args.nochanged_url}", "INFO", self.args.json))
        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Discovery-type.....: Brute force", "INFO", self.args.json or args.wordlist or args.parse_only or args.backups_only))
        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Discovery-type.....: Complete backups only", "INFO", self.args.json or not args.backups_only))
        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Discovery-type.....: Dictionary", "INFO", self.args.json or not args.wordlist))
        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Discovery-type.....: Crawling", "INFO", self.args.json or not args.parse_only))
        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Wordlist...........: {str(args.wordlist)}", "INFO", self.args.json or not args.wordlist))
        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Extensions.........: {self.args.extensions}", "INFO", self.args.json))
        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Method.............: {self.args.method}", "INFO", self.args.json))
        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"String starts......: {self.args.begin_with}", "INFO", self.args.json or not self.args.begin_with))
        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Is in response.....: {self.args.string_in_response}", "INFO", self.args.json or not self.args.string_in_response))
        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Is not in response.: {self.args.string_not_in_response}", "INFO", self.args.json or not self.args.string_not_in_response))
        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Charset............: {''.join(self.args.charset)}", "INFO", self.args.json or args.wordlist or args.parse_only))
        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Length-min.........: {self.args.length_min}", "INFO", self.args.json or args.parse_only))
        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Length-max.........: {self.args.length_max}", "INFO", self.args.json or args.parse_only))
        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Keyspace...........: {Keyspace.space}", "INFO", self.args.json or args.parse_only))
        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Delay..............: {self.args.delay}s", "INFO", self.args.json))
        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Threads............: {self.args.threads}", "INFO", self.args.json))
        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Recurse............: {self.args.recurse}", "INFO", self.args.json))
        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Parse content......: {self.args.parse}", "INFO", self.args.json))
        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Search for backups.: {self.args.backups}", "INFO", self.args.json))

        ptprinthelper.ptprint( ptprinthelper.out_ifnot(f" ", "", self.args.json))


    def determine_keyspace_complete(self, parse_only: bool) -> None:
        """
        Finalize the complete keyspace size.

        Sets the complete keyspace equal to the main keyspace, unless in parse-only mode,
        in which case it is set to 1.

        Args:
            parse_only (bool): Whether parse-only mode is active.
        """
        Keyspace.space_complete = Keyspace.space
        if parse_only:
            Keyspace.space_complete = 1


    def process_directory(self, args: ArgumentOptions) -> None:
        """
        Process a single directory by performing discovery using brute force or wordlists.

        Args:
            args (ArgumentOptions): Parsed and processed command-line arguments.
        """
        self.counter = 0
        self.start_dict_time = time.time()
        ptprinthelper.clear_line_ifnot(condition = self.args.json)
        ptprinthelper.ptprint( ptprinthelper.out_title_ifnot("Check " + self.domain_with_protocol + self.directory, self.args.json))

        if not self.check_posibility_testing():
            self.printlock.lock_print( ptprinthelper.out_ifnot("Not posible to check this directory. Use -sy, -sn or -sc parameter.", "ERROR", self.args.json), end="\n", clear_to_eol=True)
            return

        if args.wordlist or args.source or args.parse_only or args.backups_only:
            if args.parse_only or args.backups_only:
                Keyspace.space = 1
                wordlist = [""]
            else:
                if args.wordlist:
                    Keyspace.space, wordlist = self.try_prepare_wordlist(args)
                if args.source:
                    wordlist = [w for w in args.source]
                    Keyspace.space = len(wordlist) * len(args.extensions)

            self.keyspace_for_directory = Keyspace.space
            self.ptthreads.threads(wordlist, self.dictionary_discover, self.args.threads)
        else:
            combinations = ptcharsethelper.get_combinations(self.args.charset, self.args.length_min, self.args.length_max)
            self.ptthreads.threads(combinations, self.bruteforce_discover, self.args.threads)

    def process_backups(self):
        """
        Search for possible backup files in discovered resources.
        """
        Findings.findings2 = Findings.findings.copy()
        self.prepare_backup()
        ptprinthelper.clear_line_ifnot(condition = self.args.json)
        ptprinthelper.ptprint( ptprinthelper.out_title_ifnot("Search for backups", self.args.json))
        self.ptthreads.threads(Findings.findings2, self.search_backups, self.args.threads)
        #ptprinthelper.ptprint( ptprinthelper.out_title_ifnot("-------------", self.args.json))
        if self.args.recurse:
            self.process_notvisited_urls()


    def process_all_backups(self):
        """
        Search for complete backups of the entire target website.
        """
        self.prepare_backup()
        self.search_for_backup_of_all(self.domain)


    def print_results(self):
        """
        Print or export the final scan results.

        Outputs discovered URLs, details, and technologies in either human-readable
        or JSON format.
        """

        if self.use_json:
            nodes: list = self.ptjsonlib.parse_urls2nodes(Findings.findings)
            self.ptjsonlib.add_nodes(nodes)
            self.ptjsonlib.set_status("finished")
            ptprinthelper.ptprint(self.ptjsonlib.get_result_json(), "", self.use_json)
        else:
            self.output_result(Findings.findings, Findings.details, Findings.technologies)
            ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Finished in {ptmisclib.time2str(time.time()-self.start_time)} - discovered: {len(Findings.findings)} items", "INFO", self.args.json))


    def dictionary_discover(self, line: str) -> None:
        """
        Perform dictionary-based discovery using the provided wordlist entry.

        Args:
            line (str): A single entry from the wordlist (optionally with technology info).
        """
        for extension in self.args.extensions:
            self.counter += 1
            self.counter_complete += 1
            string = line.split("::")
            try:
                technology = string[1]
            except:
                technology = None
            if (string[0] == "" or string[0].endswith("/")) and extension == "/":
                continue
            if self.args.is_star:
                request_url = self.args.url[:self.args.position] + self.directory + self.args.prefix + string[0] + self.args.suffix + extension + self.args.url[self.args.position:]
            else:
                request_url = self.domain_with_protocol + self.directory + self.args.prefix + string[0] + self.args.suffix + extension
            self.prepare_and_send_request(request_url, string[0], technology)


    def bruteforce_discover(self, combination: str) -> None:
        """
        Perform brute force discovery using a generated character combination.

        Args:
            combination (str): A string combination from the charset keyspace.
        """
        if not self.args.case_insensitive and "capitalize" in self.args.charsets:
            combination = combination.capitalize()
        for extension in self.args.extensions:
            self.counter += 1
            self.counter_complete += 1
            if self.args.is_star:
                request_url = self.args.url[:self.args.position] + self.directory + self.args.prefix + ''.join(combination) + self.args.suffix + extension + self.args.url[self.args.position:]
            else:
                request_url = self.domain_with_protocol + self.directory + self.args.prefix + ''.join(combination) + self.args.suffix + extension
            self.prepare_and_send_request(request_url, ''.join(combination))


    def process_notvisited_urls(self) -> None:
        """
        Process all URLs that have been discovered but not yet visited.

        In parse mode, this continues recursively discovering new URLs.
        """
        #TODO Run brute force or directory for every new directory
        if self.args.parse:
            ptprinthelper.clear_line_ifnot(condition = self.args.json)
            ptprinthelper.ptprint( ptprinthelper.out_title_ifnot("Checking not visited sources", self.args.json))
            while True:
                if not self.get_notvisited_urls():
                    break
                self.ptthreads.threads(self.get_notvisited_urls(), self.process_notvisited, self.args.threads)


    def get_notvisited_urls(self) -> list[str]:
        """
        Get a list of URLs that have been discovered but not yet visited.

        Returns:
            list[str]: A list of unvisited URLs.
        """
        not_visited_urls = []
        for url in Findings.findings:
            if not Url(url).is_url_dictionary() and url not in Findings.visited:
                not_visited_urls.append(url)
            elif Url(url).is_url_dictionary() and (url[:-1] not in Findings.visited and url not in Findings.visited):
                not_visited_urls.append(url)
        return not_visited_urls


    def process_notvisited(self, url: str) -> None:
        """
        Visit and process a single unvisited URL.

        Args:
            url (str): The URL to visit and process.
        """
        self.prepare_and_send_request(url, "")


    def prepare_and_send_request(self, url: str, combination: str, technology:str = None) -> None:
        """
        Prepare and send a request to a target URL, then process the response.

        Args:
            url (str): The full request URL.
            combination (str): The tested string combination or wordlist entry.
            technology (str, optional): Technology tag associated with the request.
        """
        response = self.try_prepare_and_send_request(url)
        if response.status_code:
            self.process_response(url, response, combination, technology)


    def try_prepare_and_send_request(self, url: str) -> requests.Response | None:
        """
        Attempt to send a request to the given URL while tracking scan progress.

        Args:
            url (str): The target URL.

        Returns:
            requests.Response | None: The HTTP response or None if the request failed.
        """
        time_to_finish_complete = self.get_time_to_finish()
        dirs_todo = len(Findings.directories) - self.directory_finished - 1
        dir_no = "(D:" + str(dirs_todo) + " / " + str(int(self.counter / Keyspace.space * 100)) + "%)" if dirs_todo else ""
        try:
            response = self.visit_send_request(url)
        except Exception as e:
            if self.args.errors:
                self.printlock.lock_print( ptprinthelper.out_ifnot(url + " : " + str(e), "ERROR", self.args.json), clear_to_eol=True)
            return None
        self.printlock.lock_print(f"{str(datetime.timedelta(seconds=time_to_finish_complete))} ({int(self.counter_complete / Keyspace.space_complete * 100)}%) {dir_no} {url}", end="\r", condition = not(self.args.json or self.args.silent), clear_to_eol=True)
        time.sleep(self.args.delay)
        return response


    def get_time_to_finish(self):
        """
        Estimate the remaining time for the scan to complete.

        Returns:
            int: Estimated remaining time in seconds.
        """
        if self.counter == 0 or self.counter_complete == 0:
            time_to_finish_complete = 0
        else:
            time_to_finish_complete = int(((time.time() - self.start_time) / self.counter_complete) * (Keyspace.space_complete - self.counter_complete))
        return time_to_finish_complete


    def visit_send_request(self, url: str) -> requests.Response:
        """
        Send an HTTP request and record the visited URL.

        Args:
            url (str): The target URL.

        Returns:
            requests.Response: The HTTP response.
        """

        response = self.send_request(url)
        Findings.visited.append(url)
        return response

    def send_request(self, url: str) -> requests.Response:
        """
        Send an HTTP request with configured method, headers, and proxy.

        Args:
            url (str): The target URL.

        Returns:
            requests.Response: The HTTP response.
        """

        headers = copy.deepcopy(self.args.headers)
        if self.args.target:
            host = urllib.parse.urlparse(url).netloc
            url = self.args.target
            headers.update({'Host': host})
        response = ptmisclib.load_url_from_web_or_temp(url, self.args.method, headers=headers, timeout=self.args.timeout, proxies=self.args.proxies, verify=False, redirects=not(self.args.not_redirect), auth=self.args.auth, cache=self.args.cache)
        return response


    def process_response(self, request_url: str, response: requests.Response, combination: str, technology:str = None) -> None:
        """
        Process an HTTP response, extract information, and record findings.

        Args:
            request_url (str): The request URL.
            response (requests.Response): The HTTP response object.
            combination (str): The tested string or combination.
            technology (str, optional): Technology tag if known.
        """
        if self.is_processable(response):
            response_processor = ResponseProcessor(self.domain_with_protocol, self.domain, self.args)
            if self.args.save and response_processor.content_shorter_than_maximum(response):
                path = Url(request_url).get_path_from_url(with_l_slash=False)
                response_processor.save_content(response.content, path, self.args.save)
            content_type, ct_bullet = response_processor.check_content_type(response, request_url)
            history = response_processor.get_response_history(response.history, self.args.json, self.args.include_parameters, self.urlpath, self.keyspace_for_directory)
            content_location = response_processor.get_content_location(self.args.include_parameters, self.urlpath, self.keyspace_for_directory, response)
            parsed_urls = response_processor.parse_html_find_and_add_urls(response, self.args.include_parameters, self.urlpath, self.keyspace_for_directory, self.domain_protocol)
            c_t, c_l = response_processor.get_content_type_and_length(response.headers)
            c_t_l = " [" + c_t + ", " + c_l + "b] "
            show_target = combination if self.args.target else response.url

            self.printlock.lock_print(
                history +
                ptprinthelper.add_spaces_to_eon(
                ptprinthelper.out_ifnot(f"[{response.status_code}] {ct_bullet} {show_target}", "OK", self.args.json) + " " +
                ptprinthelper.out_ifnot(f"{technology}", "INFO", self.args.json or not technology), len(c_t_l), condition=self.args.json) +
                ptprinthelper.out_ifnot(c_t_l, "", self.args.json) + parsed_urls + content_location, clear_to_eol=True)
            response_processor.parse_url_and_add_unigue_url_and_directories(response.url, self.args.include_parameters, self.urlpath, self.keyspace_for_directory, response)
            if technology:
                response_processor.add_unigue_technology_to_technologies(technology)
        elif response.url in Findings.findings:
            Findings.findings.remove(response.url)


    def is_processable(self, response: requests.Response):
        """
        Determine if the response should be processed based on status codes or content.

        Args:
            response (requests.Response): The HTTP response.

        Returns:
            bool: True if processable, False otherwise.
        """
        return (
            (not self.args.string_in_response and not self.args.string_not_in_response and response.status_code not in self.args.status_codes)
            or (self.args.string_in_response and self.args.string_in_response in response.text)
            or (self.args.string_not_in_response and not self.args.string_not_in_response in response.text)
        )


    def check_posibility_testing(self) -> bool:
        """
        Test if discovery is possible in the current directory.

        Returns:
            bool: True if possible, False otherwise.
        """
        if self.args.is_star_in_domain:
            return True
        else:
            directory = self.directory if self.directory.endswith("/") else self.directory + "/"
            request_url = self.domain_with_protocol + directory + 'abc12321cba'
        try:
            response = ptmisclib.load_url_from_web_or_temp(request_url, self.args.method, headers=self.args.headers, timeout=self.args.timeout, proxies=self.args.proxies, verify=False, redirects=True, cache=self.args.cache)
        except Exception as e:
            print(e)
            self.ptjsonlib.end_error("Connection error when running posibility testing check", self.args.json)
        return (response.status_code in self.args.status_codes) or (self.args.string_in_response and self.args.string_in_response in response.text) or (self.args.string_not_in_response and not self.args.string_not_in_response in response.text)


    def check_args_combinations(self) -> None:
        """
        Validate that provided argument combinations are compatible.

        Raises errors for unsupported combinations (e.g., using '*' with backups).
        """
        if self.args.is_star:
            if self.args.backups or self.args.backups_only:
                self.ptjsonlib.end_error("Cannot find backups with '*' character in url", self.args.json)
            if self.args.parse or self.args.parse_only:
                self.ptjsonlib.end_error("Cannot use HTML parse with '*' character in url", self.args.json)
            if self.args.recurse:
                self.ptjsonlib.end_error("Cannot use recursivity with '*' character in url",  self.args.json)
        if self.args.is_star_in_domain:
            if self.args.extensions != [""] or self.args.extensions_file:
                print(self.args.extensions, self.args.extensions_file)
                self.ptjsonlib.end_error("Cannot use extensions with '*' character in domain", self.args.json)
            if self.args.tree:
                self.ptjsonlib.end_error("Cannot use tree output with '*' character in domain", self.args.json)
            if self.args.without_domain:
                self.ptjsonlib.end_error("Cannot use output without domain with '*' character in domain", self.args.json)
        if self.args.wordlist and (self.args.backups_only or self.args.parse_only):
                self.ptjsonlib.end_error("Cannot use wordlist with parameters --parse-only and --backup-only", self.args.json)


    def prepare_not_directories(self, not_directories: list[str]) -> None:
        """
        Normalize and store directories to exclude from scanning.

        Args:
            not_directories (list[str]): List of directories to exclude.
        """
        for nd in not_directories:
            nd = nd if nd.startswith("/") else "/"+nd
            nd = nd if nd.endswith("/") else nd+"/"


    def prepare_extensions(self, args: ArgumentOptions) -> list[str]:
        """
        Prepare the list of file extensions to test.

        Args:
            args (ArgumentOptions): Parsed and processed command-line arguments.

        Returns:
            list[str]: List of file extensions.
        """
        exts = ["", "/"] if self.args.directory else []
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


    def try_prepare_wordlist(self, args: ArgumentOptions) -> tuple[int, list[str]]:
        """
        Safely prepare a wordlist, handling file errors.

        Args:
            args (ArgumentOptions): Parsed and processed command-line arguments.

        Returns:
            tuple[int, list[str]]: (keyspace size, prepared wordlist).
        """
        try:
            return self.prepare_wordlist(args)
        except FileNotFoundError as e:
            self.ptjsonlib.end_error(f"Wordlist {e.filename} not found", self.args.json)
        except PermissionError as e:
            self.ptjsonlib.end_error(f"Do not have permissions to open {e.filename}", self.args.json)


    def prepare_wordlist(self, args: ArgumentOptions) -> tuple[int, list[str]]:
        """
        Load and process the wordlist(s) according to charset and filters.

        Args:
            args (ArgumentOptions): Parsed and processed command-line arguments.

        Returns:
            tuple[int, list[str]]: (keyspace size, prepared wordlist).
        """

        wordlist_complete = [""]
        for wl in args.wordlist:
            with open(wl, encoding='utf-8', errors='ignore') as f:
                wordlist = list(f)
                wordlist = [item.strip() for item in wordlist if item.startswith(self.args.begin_with) and len(item) >= self.args.length_min and len(item) <= self.args.length_max]
            if args.case_insensitive or "lowercase" in args.charsets:
                wordlist = [item.lower() for item in wordlist]
                wordlist_complete += wordlist
            if not args.case_insensitive and "uppercase" in args.charsets:
                wordlist = [item.upper() for item in wordlist]
                wordlist_complete += wordlist
            if not args.case_insensitive and "capitalize" in args.charsets:
                wordlist = [item.capitalize() for item in wordlist]
                wordlist_complete += wordlist
            if not args.case_insensitive and not "lowercase" in args.charsets and not "uppercase" in args.charsets and not "capitalize" in args.charsets:
                wordlist_complete += wordlist
        wordlist_complete = list(dict.fromkeys(list(wordlist_complete)))
        return len(wordlist_complete) * len(self.args.extensions), wordlist_complete


    def get_star_position(self, url:str) -> tuple[int, str]:
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
            return (len(url), url)


    def prepare_backup(self) -> None:
        """
        Prepare backup-related extensions and counters for backup file discovery.
        """
        self.backup_exts       = [".bak", ".old", ".zal", ".zip", ".rar", ".tar", ".tar.gz", ".tgz", ".7z"]
        self.backup_all_exts   = [".zip", ".rar", ".tar", ".tar.gz", ".tgz", ".7z", ".sql", ".sql.gz"]
        self.delimeters        = ["", "_", ".", "-"]
        self.backup_chars      = ["_", "~", ".gz"]
        self.wordlist          = []
        self.counter           = 0
        Keyspace.space         = (len(self.backup_exts) * len(Findings.findings) * 2) + (len(self.backup_chars) * len(Findings.findings)) + (len(self.backup_all_exts) * len(self.domain.split(".")) * 2)
        Keyspace.increment_space_complete_by(Keyspace.space)


    def search_backups(self, url: str) -> None:
        """
        Search for backup versions of a specific resource.

        Args:
            url (str): The base resource URL.
        """
        #ptprinthelper.ptprint( ptprinthelper.out_title_ifnot("-------------", self.args.json))
        try:
            response = ptmisclib.load_url_from_web_or_temp(url+"abc12321cba", self.args.method, headers=self.args.headers, proxies=self.args.proxies, verify=False, redirects=False, auth=self.args.auth, cache=self.args.cache)
            if ResponseProcessor(self.domain_with_protocol, self.domain, self.args).is_response(response) and not str(response.status_code).startswith("4"):
                return
        except:
            pass
        for backup_char in self.backup_chars:
            self.search_for_backup_of_source(url, backup_char, old_ext=False, char_only=True)
        for backup_ext in self.backup_exts:
            self.search_for_backup_of_source(url, backup_ext, old_ext=True,  char_only=False)
            self.search_for_backup_of_source(url, backup_ext, old_ext=False, char_only=False)

    def search_for_backup_of_all(self, domain: str) -> None:
        """
        Search for backups of the entire domain.

        Args:
            domain (str): The target domain.
        """
        ptprinthelper.clear_line_ifnot(condition = self.args.json)
        ptprinthelper.ptprint( ptprinthelper.out_title_ifnot("Search for completed backups of the website", self.args.json))
        self.start_dict_time = time.time()
        self.counter = 0
        Keyspace.space = len(self.backup_all_exts) * len(domain.split(".")) * len(self.delimeters) * len(domain.split(".")) / 2 - (len(self.backup_all_exts) * (len(self.delimeters) - 1))
        Keyspace.increment_space_complete_by(Keyspace.space)
        self.directory_finished = 0
        for i in range(1, len(domain.split("."))):
            for d, delimeter in enumerate(self.delimeters):
                self.domain_back_name = ""
                for s, subdomain in enumerate(domain.split(".")[i:]):
                    self.domain_back_name += subdomain
                    if d > 0 and s == 0:
                        self.domain_back_name += delimeter
                        continue
                    self.ptthreads.threads(self.backup_all_exts.copy(), self.search_for_backup_of_all_exts, self.args.threads)
                    self.domain_back_name += delimeter


    def search_for_backup_of_all_exts(self, ext: str) -> None:
        """
        Search for complete site backups with a specific extension.

        Args:
            ext (str): The backup file extension.
        """
        self.counter += 1
        self.counter_complete += 1
        self.prepare_and_send_request(self.domain_with_protocol + "/" + self.domain_back_name + ext, "")


    def search_for_backup_of_source(self, url: str, ext: str, old_ext: bool, char_only: bool) -> None:
        """
        Search for backup versions of a specific source file.

        Args:
            url (str): The base file URL.
            ext (str): The backup file extension or delimiter.
            old_ext (bool): Whether to search using the original extension.
            char_only (bool): Whether the ext argument is a delimiter/character only.
        """
        self.counter += 1
        self.counter_complete += 1
        if char_only:
            try:
                patern = r'^((https?|ftps?)://[^?#"\'\s]*/[^?#"\'\s]*)[?#"\'\s]*' #r'^((https?|ftps?):\/\/[^?#"\'\s]*\/[^?#"\'\s]*)[\\?#"\'\s]*'
                url = list(list({result for result in re.findall(patern, url)})[0])[0]
                self.prepare_and_send_request(url + ext, "")
            except:
                return
        if old_ext:
            if Url(url).is_url_dictionary():
                return
            self.prepare_and_send_request(url + ext, "")
        else:
            if Url(url).is_url_dictionary() and not url[:-1] == self.domain_with_protocol:
                self.prepare_and_send_request(url[:-1] + ext, "")
            else:
                try:
                    patern = r'((https?|ftps?)://[^?#"\'\s]*/[^?#"\'\s]*)\.[?#"\'\s]*' #r'((https?|ftps?):\/\/[^?#"\'\s]*\/[^?#"\'\s]*)\.[?#"\'\s]*'
                    url_without_ext = list(list({result for result in re.findall(patern, url)})[0])[0]
                    self.prepare_and_send_request(url_without_ext + ext, "")
                except:
                    return


    def output_result(self, findings: list[str], findings_details: list[FindingDetail], technologies: list[str]) -> None:
        """
        Output discovered findings and technologies.

        Args:
            findings (list[str]): List of discovered URLs.
            findings_details (list[FindingDetail]): Detailed findings with headers.
            technologies (list[str]): List of detected technologies.
        """

        ptprinthelper.clear_line_ifnot(condition=self.args.json)
        if findings:
            if self.args.without_domain:
                findings = [url.replace(self.domain_with_protocol, "") for url in findings]
            ptprinthelper.ptprint( ptprinthelper.out_title_ifnot("Discovered sources", self.args.json))
            if self.args.tree:
                self.output_tree(findings)
            else:
                self.output_list(findings, findings_details)
            ptprinthelper.clear_line_ifnot(condition=self.args.json)
        if technologies:
            ptprinthelper.ptprint( ptprinthelper.out_title_ifnot("Discovered technologies", self.args.json))
            self.output_list(technologies)
            ptprinthelper.clear_line_ifnot(condition=self.args.json)


    def output_list(self, line_list: list[str], line_list_details: list[FindingDetail] = []) -> None:
        """
        Output a list of findings to console and optionally to file.

        Args:
            line_list (list[str]): List of findings.
            line_list_details (list[FindingDetail], optional): Detailed findings.
        """
        line_list = sorted(list(dict.fromkeys(list(line_list))))
        output_file = None
        output_file_detail = None
        if self.args.output:
            output_file = open(self.args.output,"w+")
            if self.args.with_headers:
                output_file_detail = open(self.args.output+".detail","w+")
        self.output_lines(line_list, line_list_details, output_file, output_file_detail)
        if self.args.output:
            output_file.close()
            if self.args.with_headers:
                output_file_detail.close()

    def output_lines(self, lines: list[str], line_list_details: list[FindingDetail], output_file: TextIOWrapper, output_file_detail: TextIOWrapper) -> None:
        """
        Write findings and their details to output.

        Args:
            lines (list[str]): List of findings.
            line_list_details (list[FindingDetail]): Details for each finding.
            output_file (TextIOWrapper): File object for basic output.
            output_file_detail (TextIOWrapper): File object for detailed output.
        """
        for line in lines:
            is_detail = None
            if self.args.with_headers:
                for line_detail in line_list_details:
                    if line_detail.url == line:
                        is_detail = True
                        ptprinthelper.ptprint( ptprinthelper.out_ifnot("[" + str(line_detail.status_code) + "]  " + line + "\n", condition=self.args.json), end="")
                        if self.args.output:
                            output_file_detail.write("[" + str(line_detail.status_code) + "]  " + line + "\r\n")
                        try:
                            for key, value in line_detail.headers.items():
                                if self.args.output:
                                    output_file_detail.write(" " * 7 + key + " : " + value + "\r\n")
                                ptprinthelper.ptprint( ptprinthelper.out_ifnot(" " * 7 + key + " : " + value, "ADDITIONS", condition=self.args.json, colortext=True))
                            break
                        except:
                            pass
                ptprinthelper.ptprint( ptprinthelper.out_ifnot("\n", condition=self.args.json))
            if not is_detail:
                ptprinthelper.ptprint( ptprinthelper.out_ifnot(line, condition=self.args.json))
                #TODO repair JSON
                if self.args.json:
                    print(line)
                if self.args.output:
                    output_file.write(line + "\r\n")
                    if self.args.with_headers:
                        output_file_detail.write(line + "\r\n")


    def output_tree(self, line_list: list[str]) -> None:
        """
        Output findings in a tree structure.

        Args:
            line_list (list[str]): List of discovered URLs.
        """
        urls = sorted(list(dict.fromkeys(list(line_list))))
        slash_correction = 2 if re.match(r'^\w{2,5}://', urls[0]) else 0
        tree = treeshow.Tree()
        tree_show = treeshow.Treeshow(tree)
        json_tree = tree_show.url_list_to_json_tree(urls)
        tree_show.createTree(None, json_tree)
        tree.show()
        if self.args.output:
            output_file = open(self.args.output,"w+")
            output_file.close()
            tree.save2file(self.args.output)

    def check_url_availability(self, url: str, proxies: dict[str,str], headers: dict[str,str], auth: tuple[str,str], method: str, position: int) -> requests.Response:
        """
        Check if the target URL is reachable and meets expected status conditions.

        Args:
            url (str): The target URL.
            proxies (dict[str, str]): Proxy settings.
            headers (dict[str, str]): HTTP headers.
            auth (tuple[str, str]): HTTP Basic authentication credentials.
            method (str): HTTP method.
            position (int): Position of wildcard or insertion point.

        Returns:
            requests.Response: The HTTP response.
        """
        extract = urllib.parse.urlparse(url)
        if not (extract.scheme == "http" or extract.scheme == "https"):
            self.ptjsonlib.end_error("Check scheme in url (allowed schemes are http:// and https://)", self.args.json)
        try:
            response = ptmisclib.load_url_from_web_or_temp(url, method, headers=headers, proxies=proxies, verify=False, redirects=True, auth=auth, cache=self.args.cache)
        except:
            self.ptjsonlib.end_error("Server not found", self.args.json)
        if self.args.is_star:
            return response
        if response.status_code == 404:
            self.ptjsonlib.end_error("Returned status code 404. Check url address.", self.args.json)
        if str(response.status_code).startswith("3"):
            url, position = self.change_schema_when_redirect_from_http_to_https(response, extract)
            try:
                response = ptmisclib.load_url_from_web_or_temp(url, method, headers=headers, proxies=proxies, verify=False, redirects=False, auth=auth, cache=self.args.cache)
            except:
                pass
        elif response.status_code == 405 or response.status_code == 501:
            self.ptjsonlib.end_error("HTTP method not supported. Use -m option for select another one.", self.args.json)
        slash = "/" if position == len(url) else ""
        try:
            response404 = ptmisclib.load_url_from_web_or_temp(url[:position] + slash + "abc45654cba" + url[position:], method, headers=headers, proxies=proxies, verify=False, redirects=True, auth=auth, cache=self.args.cache)
            if response404.status_code != 404 and not self.args.string_in_response and not self.args.string_not_in_response:
                self.ptjsonlib.end_error(f"Unstable server reaction: Nonexistent page return status code {response.status_code}. Use -sy or -sn parameter.", self.args.json)
            return response
        except Exception as e:
            self.ptjsonlib.end_error(e, self.args.json)


    def change_schema_when_redirect_from_http_to_https(self, response: requests.Response, old_extract: urllib.parse.ParseResult) -> tuple[str,int]:
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
            self.args.url  = self.args.url.replace("http", "https", 1)
            self.domain_with_protocol = self.domain_with_protocol.replace("http://", "https://", 1)
            self.domain_protocol = "https"
            self.args.position += 1
        else:
            ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Returned status code {response.status_code}. Site redirected to {target_location}. Check target in -u option.\n", "ERROR", self.args.json), end="\n", clear_to_eol=True)
        return (self.args.url, self.args.position)


    def get_and_set_cookies(self, response: requests.Response) -> str:
        """
        Extract cookies from a response and append configured cookies.

        Args:
            response (requests.Response): HTTP response object.

        Returns:
            str: Combined cookie string.
        """
        cookies = ""
        try:
            if not self.args.refuse_cookies:
                for c in response.raw.headers.getlist('Set-Cookie'):
                    cookies += c.split("; ")[0] + "; "
        except:
            pass
        cookies += self.args.cookie
        return cookies


def get_help():
    return [
        {"description": ["Web Source Discovery Tool"]},
        {"usage": [f"ptwebdiscover <options>"]},
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
        ]},
        {"options": [
            ["-u",  "--url",                    "<url>",            "URL for test (usage of a star character as anchor)"],
            ["-ch", "--charsets",               "<charsets>",       "Specify charset for brute force (example: lowercase,uppercase,numbers,[custom_chars])"],
            ["",    "",                         "",                 "Modify wordlist (lowercase,uppercase,capitalize)"],
            ["-src", "--source",               "<source>",          "Check for presence of only specified <source> (eg. -src robots.txt)"],
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
            ["-b",  "--backups",                "",                 "Find backups for db, all app and every discovered content"],
            ["-bo", "--backups-only",           "",                 "Find backup of complete website only"],
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
            ["-er", "--errors",                 "",                 "Show all errors"],
            ["-v",  "--version",                "",                 "Show script version"],
            ["-h",  "--help",                   "",                 "Show this help message"],
            ["-j",  "--json",                   "",                 "Output in JSON format"],
        ]},
    ]


def parse_args() -> ArgumentOptions:
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
    parser.add_argument("-bo", "--backups-only", action="store_true")
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
    parser.add_argument("-sc", "--status-codes", type=int, nargs="+", default=[404])
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
    parser.add_argument("-v",  "--version", action="version", version=f"{SCRIPTNAME} {__version__}")
    parser.add_argument("-C",  "--cache", action="store_true")
    parser.add_argument("-j",  "--json", action="store_true")

    parser.add_argument("--socket-address",          type=str, default=None)
    parser.add_argument("--socket-port",             type=str, default=None)
    parser.add_argument("--process-ident",           type=str, default=None)


    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)


    args = parser.parse_args()

    # Handle -src as full URL
    if args.source and isinstance(args.source, list) and args.source[0].startswith(("http://", "https://")):
        parsed = urlparse(args.source[0])
        # Set URL from src
        args.url = f"{parsed.scheme}://{parsed.netloc}"
        # Set relative path as src
        args.source = [parsed.path.lstrip("/")]
        return ArgumentOptions(**vars(args))

    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptwebdiscover"
    requests.packages.urllib3.disable_warnings()
    args = parse_args()
    script = PtWebDiscover(args)
    script.run(args)


if __name__ == "__main__":
    main()
