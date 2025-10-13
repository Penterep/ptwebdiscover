#!/usr/bin/python3
"""
Copyright (c) 2025 Penterep Security s.r.o.

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
import copy
import requests
import shutil

from urllib.parse import urlparse


import helpers
import results

from ptlibs import ptnethelper, ptcharsethelper, ptprinthelper, ptjsonlib, ptmisclib
from ptlibs.ptprinthelper import ptprint
from ptlibs.threads import ptthreads, printlock, arraylock

from ptdataclasses.argumentoptions import ArgumentOptions

from utils import args_processing
from utils import treeshow
from utils.url import Url
from utils.robots_txt_parser import RobotsTxtParser
from responseprocessing import ResponseProcessor
from findings import Findings
from keyspace import Keyspace


from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.web_archive import WebArchiveCrawler

class PtWebDiscover():
    def __init__(self, args: ArgumentOptions) -> None:
        """
        Initialize the PtWebDiscover instance.

        Args:
            args (ArgumentOptions): Parsed and processed command-line arguments.
        """
        self.args                            = args

        self.ptjsonlib                       = ptjsonlib.PtJsonLib()
        self.ptthreads                       = ptthreads.PtThreads()
        self.printlock                       = printlock.PrintLock()
        self.arraylock                       = arraylock.ArrayLock()

        self.domain                          = Url(args.url).get_domain_from_url(level=True, with_protocol=False)       # www.example.com
        self.domain_with_protocol            = Url(args.url).get_domain_from_url(level=True, with_protocol=True)        # https://www.example.com
        self.urlpath                         = Url(args.url).get_path_from_url(with_l_slash=True, without_r_slash=True) # /index.php
        self.domain_protocol                 = urllib.parse.urlparse(args.url).scheme                                   # http

        self.keyspace_for_directory          = Keyspace.space
        Findings.directories                 = arraylock.ThreadSafeArray([self.urlpath + "/"] if not args.is_star else [""])

        #self._prepare_not_directories(args.not_directories) # TODO: FIXME: Unused code

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
            response = self._check_url_availability(self.args.url, self.args.proxies, self.args.headers, self.args.auth, self.args.method, self.args.position)
            self.args.headers["Cookie"] = self._set_header_cookies(response)

        self.initialize_counters() #  Prepares timing and progress tracking.

        if self.args.archive: # WebArchive scan
            self.webarchive_crawler = WebArchiveCrawler(self.args, self.ptjsonlib)
            url_list = self.webarchive_crawler.run(self.args.url)
            if "checked" in str(args.archive):
                # set wordlist and keep going
                ptprinthelper.ptprint(f"Extracted {len(url_list)} urls to be checked\n", "", condition=not self.args.json, clear_to_eol=True, indent=4)

                args.wordlist = [self.webarchive_crawler.wordlist_path]
            else:
                # Add to result and quit
                Findings.findings.extend(url_list)
                self.print_results()
                return

        self.determine_keyspace(args)                        # Calculates how many payloads (wordlist entries or brute-force combinations) will be tested.
        helpers.print_configuration(args, Keyspace.space)    # Outputs the current settings so the user can see what will be tested.

        if args.non_exist: # send request to non existing source
            self.check_status_for_non_existing_resource(args)

        # args.url + source
        if args.source and args.source[0].startswith(("http://", "https://")):
            response = self.prepare_and_send_request(args.source[0], "")
            if response:
                if self.args.vuln_yes:
                    self.ptjsonlib.add_vulnerability(self.args.vuln_yes)
            else:
                ptprinthelper.ptprint("Source not available", "ERROR", condition=not self.args.json, clear_to_eol=True)
                if self.args.vuln_no:
                    self.ptjsonlib.add_vulnerability(self.args.vuln_no)
        else:
            if self.args.backup_all and not self.args.wordlist:
                pass
            else:
                # Bruteforce/Wordlist test
                for self.directory_finished, self.directory in enumerate(Findings.directories):
                    self.process_directory(args)

        if self.args.recurse:
            self.process_notvisited_urls()

        if self.args.backups:
            self.process_backups()

        if self.args.backup_all:
            self.process_backup_all()

        self.print_results()

    def _prepare_not_directories(self, not_directories: list[str]) -> None:
        """
        Normalize and store directories to exclude from scanning.

        Args:
            not_directories (list[str]): List of directories to exclude.
        """
        # FIXME: Add purpose / logic

        for nd in not_directories:
            nd = nd if nd.startswith("/") else "/"+nd
            nd = nd if nd.endswith("/") else nd+"/"

    def check_status_for_non_existing_resource(self, args):
        """
        Test server behavior for a non-existing resource.

        Sends a request to a deliberately non-existent file and checks the response
        status code. If the server incorrectly returns 200 OK, a vulnerability flag
        is recorded and program terminated.

        Args:
            args (ArgumentOptions): Parsed and processed command-line arguments.
        """
        ptprinthelper.ptprint("Check status for not-existing resource", "TITLE", condition=not self.args.json, colortext=True)

        url = args.url + "/this-resource-does-not-exist"
        ptprinthelper.ptprint(f"Sending request to: {url}", "INFO", condition=not self.args.json)
        response = self._send_request(url)

        ptprinthelper.ptprint(f"Returned status code: {response.status_code}", "INFO", condition=not self.args.json)

        if response.status_code == 200:# in [200, ]:
            self.ptjsonlib.add_vulnerability("PTV-WEB-INJECT-REFLEXURL")
            self.ptjsonlib.end_ok("Server returned SC 200 for not-existing resources", self.args.json, bullet_type="VULN")
        else:
            self.ptjsonlib.end_ok(f"Server returned status code {response.status_code} for non existing resource", self.args.json, bullet_type="OK")


    def cache_dns(self) -> None:
        """
        Cache DNS lookups for improved performance.

        This function imports and initializes DNS cache handling utilities.
        """
        from utils import cachefile


    def _set_header_cookies(self, response):
        """
        Set the 'Cookie' header in the request headers.
        """

        cookies = ""
        try:
            if not self.args.refuse_cookies:
                for c in response.raw.headers.getlist('Set-Cookie'):
                    cookies += c.split("; ")[0] + "; "
        except (AttributeError, KeyError):
            pass
        cookies += self.args.cookie
        return cookies

    def initialize_counters(self):
        self.start_time = time.time()
        self.counter_complete = 0
        self.directory_finished = 0
        self.counter = 0


    def determine_keyspace(self, args: ArgumentOptions) -> None:
        """
        Determine the total keyspace of possible payloads to test.

        If a wordlist is provided, the keyspace is derived from it. Otherwise, it is
        generated from the provided charset, length constraints, and file extensions.

        Sets the complete keyspace equal to the main keyspace, unless in parse-only mode,
        in which case it is set to 1.

        Args:
            args (ArgumentOptions): Parsed and processed command-line arguments.
        """
        if args.wordlist:
            Keyspace.space, _ = self.prepare_wordlist(args)
        else:
            Keyspace.space = ptcharsethelper.get_keyspace(args.charset, args.length_min, args.length_max, len(args.extensions))

        Keyspace.space_complete = Keyspace.space
        if args.parse_only:
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

        if args.wordlist or args.source or args.parse_only or args.backup_all:
            if args.parse_only or args.backup_all:
                Keyspace.space = 1
                wordlist = [""]
            else:
                if args.wordlist:
                    Keyspace.space, wordlist = self.prepare_wordlist(args)
                if args.source:
                    wordlist = [w for w in args.source]
                    Keyspace.space = len(wordlist) * len(args.extensions)
            self.keyspace_for_directory = Keyspace.space
            self.ptthreads.threads(wordlist, self.dictionary_discover, self.args.threads)
        else:
            combinations = ptcharsethelper.get_combinations(self.args.charset, self.args.length_min, self.args.length_max)
            self.ptthreads.threads(combinations, self.bruteforce_discover, self.args.threads)

    def process_backups(self) -> None:
        """
        Search for possible backup files in discovered resources.
        """
        self.init_backup_test()

        Findings.findings2 = Findings.findings.copy()
        ptprinthelper.clear_line_ifnot(condition = self.args.json)
        ptprinthelper.ptprint( ptprinthelper.out_title_ifnot("Search for backups", self.args.json))

        found_backups = []

        # Find backups for found sources
        for finding in Findings.findings2:
            found_backups.extend(self.search_backups(url=finding))

        # Check for backups of base url
        if self.args.source:
            url = self.args.url
            if not url.endswith("/"):
                url += "/"
            url += self.args.source[0].lstrip("/")

            if url not in Findings.findings2:
                found_backups.extend(self.search_backups(url=url))

        if not found_backups and not self.args.recurse:
            ptprint("No backups found", "NOTVULN", condition=not self.args.json, clear_to_eol=True)

        if self.args.recurse:
            self.process_notvisited_urls()

    def process_backup_all(self):
        """
        Search for complete backups of the entire target website.
        """
        self.init_backup_test()
        self.search_for_backup_of_all(self.domain)


    def print_results(self):
        """
        Print or export the final scan results.

        Outputs discovered URLs, details, and technologies in either human-readable
        or JSON format.
        """
        if self.args.json:
            nodes: list = self.ptjsonlib.parse_urls2nodes(Findings.findings)
            self.ptjsonlib.add_nodes(nodes)
            self.ptjsonlib.set_status("finished")
            ptprinthelper.ptprint(self.ptjsonlib.get_result_json(), "", self.args.json)
        else:
            results.output_result(self.args, Findings.findings, Findings.details, Findings.technologies)
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

            response = self.prepare_and_send_request(request_url, string[0], technology)
            if response:
                if self.args.vuln_yes:
                    if urlparse(response.url).path == "/":
                        return
                    self.ptjsonlib.add_vulnerability(self.args.vuln_yes)
            else:
                if self.args.vuln_no:
                    self.ptjsonlib.add_vulnerability(self.args.vuln_no)


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
            response = self.prepare_and_send_request(request_url, ''.join(combination))

            if response and self.args.vuln_yes:
                self.ptjsonlib.add_vulnerability(self.args.vuln_yes)
            if not response and self.args.vuln_no:
                self.ptjsonlib.add_vulnerability(self.args.vuln_no)

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

        Returns:
            bool: True if the response status code is 200, False otherwise.
        """
        response = self._try_prepare_and_send_request(url)

        if response.status_code:
            self._process_response(url, response, combination, technology)

        return response
        #return True if response.status_code == 200 else False

    def _try_prepare_and_send_request(self, url: str) -> requests.Response | None:
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
            response = self._send_request(url)
            Findings.visited.append(url)
        except Exception as e:
            if self.args.errors:
                self.printlock.lock_print( ptprinthelper.out_ifnot(url + " : " + str(e), "ERROR", self.args.json), clear_to_eol=True)
            raise e
            #return None

        term_width = shutil.get_terminal_size((100, 20)).columns
        time_str = str(datetime.timedelta(seconds=time_to_finish_complete))
        percent = int(self.counter_complete / Keyspace.space_complete * 100)
        fixed_part = f"{time_str} ({percent}%) {dir_no} "

        available_for_url = term_width - len(fixed_part) - 2
        short_url = helpers.shorten_url_middle(url, available_for_url)
        line = f"{fixed_part}{short_url}"
        self.printlock.lock_print(
            line,
            end="\r",
            condition=not (self.args.json or self.args.silent),
            clear_to_eol=True
        )
        #self.printlock.lock_print(f"{str(datetime.timedelta(seconds=time_to_finish_complete))} ({int(self.counter_complete / Keyspace.space_complete * 100)}%) {dir_no} {url}", end="\r", condition = not(self.args.json or self.args.silent), clear_to_eol=True)
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



    def _send_request(self, url: str) -> requests.Response:
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


    def _is_processable(self, response: requests.Response):
        """
        Determine if the response should be processed based on status codes or content.

        Args:
            response (requests.Response): The HTTP response.

        Returns:
            bool: True if processable, False otherwise.
        """
        return (
            (
                # status_code must be allowed (if list is not empty)
                (not self.args.status_code_yes or response.status_code in self.args.status_code_yes)
                # status_code must not be denied
                and response.status_code not in self.args.status_code_no
                # no string checks
                and not self.args.string_in_response
                and not self.args.string_not_in_response
            )
            # string must exist
            or (self.args.string_in_response and self.args.string_in_response in response.text)
            # string must not exist
            or (self.args.string_not_in_response and self.args.string_not_in_response not in response.text)
        )

    def _process_response(self, request_url: str, response: requests.Response, combination: str, technology:str = None) -> None:
        """
        Process an HTTP response, extract information, and record findings.

        Args:
            request_url (str): The request URL.
            response (requests.Response): The HTTP response object.
            combination (str): The tested string or combination.
            technology (str, optional): Technology tag if known.
        """
        if self._is_processable(response):
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

            if not self.args.json:
                self.printlock.lock_print(
                    history +
                    ptprinthelper.add_spaces_to_eon(
                    ptprinthelper.out_ifnot(f"[{response.status_code}] {ct_bullet} {show_target}", "OK", self.args.json) + " " +
                    ptprinthelper.out_ifnot(f"{technology}", "INFO", self.args.json or not technology), len(c_t_l), condition=self.args.json) +
                    ptprinthelper.out_ifnot(c_t_l, "", self.args.json) + parsed_urls + content_location, clear_to_eol=True)

            response_processor.parse_url_and_add_unique_url_and_directories(response.url, self.args.include_parameters, self.urlpath, self.keyspace_for_directory, response)

            if technology:
                response_processor.add_unique_technology_to_technologies(technology)

        elif response.url in Findings.findings:
            Findings.findings.remove(response.url)

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
            self.ptjsonlib.end_error(f"Connection error when running posibility testing check", condition=self.args.json, details=str(e))
        return (response.status_code in self.args.status_code_no) or (self.args.string_in_response and self.args.string_in_response in response.text) or (self.args.string_not_in_response and not self.args.string_not_in_response in response.text)

    def prepare_wordlist(self, args: ArgumentOptions) -> tuple[int, list[str]]:
        """
        Load and process the wordlist(s) according to charset and filters.

        Args:
            args (ArgumentOptions): Parsed and processed command-line arguments.

        Returns:
            tuple[int, list[str]]: (keyspace size, prepared wordlist).
        """
        wordlist_complete = [""]
        try:
            for wl in args.wordlist:
                with open(wl, encoding='utf-8', errors='ignore') as f:
                    wordlist = list(f)
                    if args.archive:
                        wordlist = [item.strip() for item in wordlist if item]
                    else:
                        wordlist = [item.strip() for item in wordlist if item.startswith(args.begin_with) and len(item) >= args.length_min and len(item) <= args.length_max]
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
            wordlist_complete = list(dict.fromkeys(wordlist_complete))
            return len(wordlist_complete) * len(args.extensions), wordlist_complete
        except FileNotFoundError as e:
            self.ptjsonlib.end_error(f"Wordlist {e.filename} not found", args.json)
        except PermissionError as e:
            self.ptjsonlib.end_error(f"Do not have permissions to open {e.filename}", args.json)


    def init_backup_test(self) -> None:
        """
        Prepare backup-related extensions and counters for backup file discovery.
        """
        self.backup_exts       = [".bak", ".old", ".zal", ".zip", ".rar", ".tar", ".tar.gz", ".tgz", ".7z"]
        self.backup_all_exts   = [".zip", ".rar", ".tar", ".tar.gz", ".tgz", ".7z", ".sql", ".sql.gz"]
        self.delimeters        = ["", "_", ".", "-"]
        self.backup_chars      = ["_", "~", ".gz"]
        self.wordlist          = []
        self.counter           = 0
        if self.args.backup_all:
            tested_exts = list(set(self.backup_exts + self.backup_all_exts))
        else:
            tested_exts = self.backup_exts
        Keyspace.increment_space_complete_by(Keyspace.space)

        #Keyspace.space = len(tested_exts) * 5
        Keyspace.space         = (len(self.backup_exts) * len(Findings.findings) * 2) + (len(self.backup_chars) * len(Findings.findings)) + (len(self.backup_all_exts) * len(self.domain.split(".")) * 2)
        #if self.args.backup_all:
            #total_extensions = list(set(self.backup_exts + self.backup_all_exts))
            #Keyspace.space = len(total_extensions) * 5
            #Keyspace.space = (len(self.backup_exts) + len(self.backup_all_exts) + len(self.delimeters) + len(self.backup_chars) + len(self.wordlist)) * 5
            #len(self.extensions)



    def search_backups(self, url: str) -> list:
        """
        Search for backup versions of a specific resource in parallel.

        This method attempts to discover potential backup files for the given URL
        using a set of predefined characters and extensions. Each combination of
        URL and backup character/extension is checked concurrently using a
        ThreadPoolExecutor with a maximum number of threads defined by `self.args.threads`.

        Args:
            url (str): The base resource URL to search backups for.

        Returns:
            result (list): List of positive findings.
        """
        results = [] # findings
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            futures = []
            for backup_char in self.backup_chars:
                futures.append(executor.submit(self.search_for_backup_of_source, url, backup_char, False, True))
            for backup_ext in self.backup_exts:
                futures.append(executor.submit(self.search_for_backup_of_source, url, backup_ext, True, False))
                futures.append(executor.submit(self.search_for_backup_of_source, url, backup_ext, False, False))

            for future in as_completed(futures):
                try:
                    if future.result():  # True = backup found
                        results.append(future.result())
                        if self.args.vuln_yes:
                            self.ptjsonlib.add_vulnerability(self.args.vuln_yes)
                    else:
                        if self.args.vuln_no:
                            self.ptjsonlib.add_vulnerability(self.args.vuln_yes)
                except Exception as e:
                    pass
        return results

    def search_for_backup_of_all(self, domain: str) -> None:
        """
        Search for backups of the entire domain.

        Args:
            domain (str): The target domain.
        """
        ptprinthelper.clear_line_ifnot(condition = self.args.json)
        ptprinthelper.ptprint( ptprinthelper.out_title_ifnot("Search for complete backups of the website", self.args.json))
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
        response = self.prepare_and_send_request(self.domain_with_protocol + "/" + self.domain_back_name + ext, "")
        if response:
            if self.args.vuln_yes:
                self.ptjsonlib.add_vulnerability(self.args.vuln_yes)

        else:
            if self.args.vuln_no:
                self.ptjsonlib.add_vulnerability(self.args.vuln_no)

    def search_for_backup_of_source(self, url: str, ext: str, old_ext: bool, char_only: bool) -> bool:
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
                return self.prepare_and_send_request(url + ext, "")
            except Exception as e:
                return False

        if old_ext:
            if Url(url).is_url_dictionary():
                return False
            return self.prepare_and_send_request(url + ext, "")

        else:

            if Url(url).is_url_dictionary() and not url[:-1] == self.domain_with_protocol:
                return self.prepare_and_send_request(url[:-1] + ext, "")

            else:
                try:
                    patern = r'((https?|ftps?)://[^?#"\'\s]*/[^?#"\'\s]*)\.[?#"\'\s]*' #r'((https?|ftps?):\/\/[^?#"\'\s]*\/[^?#"\'\s]*)\.[?#"\'\s]*'
                    url_without_ext = list(list({result for result in re.findall(patern, url)})[0])[0]
                    return self.prepare_and_send_request(url_without_ext + ext, "")
                except Exception as e:
                    return False
        return False

    def _check_url_availability(self, url: str, proxies: dict[str,str], headers: dict[str,str], auth: tuple[str,str], method: str, position: int) -> requests.Response:
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
        """
        if not url.endswith("/") and position == len(url):
            url += "/"
            position, _ = helpers.get_star_position(url)
        """

        extract = urllib.parse.urlparse(url)
        try:
            response = ptmisclib.load_url_from_web_or_temp(url, method, headers=headers, proxies=proxies, verify=False, redirects=False, auth=auth, cache=self.args.cache)
            if self.args.is_star:
                return response

            if response.is_redirect:
                url, position = self._change_schema_when_redirect_from_http_to_https(response, extract)
                try:
                    response = ptmisclib.load_url_from_web_or_temp(url, method, headers=headers, proxies=proxies, verify=False, redirects=False, auth=auth, cache=self.args.cache)
                except:
                    pass

            if response.status_code == 404:
                self.ptjsonlib.end_error("Returned status code 404. Check url address.", self.args.json)

            elif response.status_code == 405 or response.status_code == 501:
                self.ptjsonlib.end_error("HTTP method not supported. Use -m option for select another one.", self.args.json)
        except Exception as e:
            self.ptjsonlib.end_error("Server not found", condition=self.args.json, details=str(e))

        """
        try:
            response404 = ptmisclib.load_url_from_web_or_temp(url[:position] +  "abc45654cbaa" + url[position:], method, headers=headers, proxies=proxies, verify=False, redirects=True, auth=auth, cache=self.args.cache)
            if response404.status_code != 404 and not self.args.string_in_response and not self.args.string_not_in_response:
                self.ptjsonlib.end_error(f"Unstable server reaction: Nonexistent page return status code {response.status_code}. Use -sy or -sn parameter.", self.args.json)
            return response
        except Exception as e:
            self.ptjsonlib.end_error(str(e), self.args.json)
        """


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
            self.args.url  = self.args.url.replace("http", "https", 1)
            self.domain_with_protocol = self.domain_with_protocol.replace("http://", "https://", 1)
            self.domain_protocol = "https"
            self.args.position += 1
        else:
            ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Returned status code {response.status_code}. Site redirected to {target_location}. Check target in -u option.\n", "ERROR", self.args.json), end="\n", clear_to_eol=True)
        return (self.args.url, self.args.position)


def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptwebdiscover"
    requests.packages.urllib3.disable_warnings()
    args = args_processing.parse_args(SCRIPTNAME)
    script = PtWebDiscover(args)
    script.run(args)


if __name__ == "__main__":
    main()
