from shutil import copy
import helpers
import re
from utils.url import Url
from ptlibs import ptprinthelper
from concurrent.futures import ThreadPoolExecutor, as_completed



class Backups:
    def __init__(self, parent):
        self.parent = parent

        self.backup_exts       = [".bak", ".old", ".zal", ".zip", ".rar", ".gz", ".tar", ".tar.gz", ".tgz", ".7z"]
        self.backup_chars      = ["_", "~"]
        self.wordlist          = []
        self.counter           = 0
        self.extension_count   = len(self.backup_exts) + len(self.backup_chars)

    def prepare_wordlist_for_backup_all(self) -> list[str]:
        # remove white chars and dots at the beginning/end
        domain = self.parent.target.domain.strip().lower().strip(".")
        segments = domain.split(".")                                                                                    # ['sub', 'www', 'example', 'com']
        segments_reverse = segments[::-1]                                                                               # ['com', 'example', 'www', 'sub']
        full_domain_combination = "**".join(segments)                                                                   # sub**www**example**com
        segment_combinations = []
        if len(segments_reverse) > 2:
            segment_combinations.append(segments_reverse[2])                                                            # www
            segment_combinations.append(segments_reverse[2] + "**" + segments_reverse[1] + "**" + segments_reverse[0])  # www**example**com
        if len(segments_reverse) > 1:
            segment_combinations.append(segments_reverse[1])                                                            # example
            segment_combinations.append(segments_reverse[1] + "**" + segments_reverse[0])                               # example**com                                     # sub**www**example**com
        if not full_domain_combination in segment_combinations:
            segment_combinations.append(full_domain_combination)

        # Get combinations where ** is replaced with various delimiters.
        combinations = []
        delimeters = ["", "-", "_", "."]
        for segment_combination in segment_combinations:
            for delimeter in delimeters:
                combinations.append(segment_combination.replace("**", delimeter))
       
        # Create wordlist with combinations of domains and extensions
        extensions = self.backup_exts.copy()
        extensions.extend([".sql", ".bak.sql", ".log", ".cfg", ".conf", ".config"])
        wordlist = []
        for combination in combinations:
            for ext in extensions:
                wordlist.append(combination + ext)

        wordlist = helpers.get_unique_list(wordlist)
        return wordlist


    def process_backups(self) -> None:
        """
        Search for possible backup files in discovered resources.
        """
        ptprinthelper.clear_line_ifnot(condition = self.parent.args.json)
        ptprinthelper.ptprint( ptprinthelper.out_title_ifnot("Search for backups", self.parent.args.json))

        self.parent.counters.reset_counter_complete()

        number_of_findings = len(self.parent.findings.findings)
        keyspace_for_backups = (number_of_findings * (len(self.backup_exts) * 2) + (number_of_findings * len(self.backup_chars))) # *2 because with and without old extension

        self.parent.counters.set_keyspace_complete(keyspace_for_backups)

        # Find backups for found sources
        for url in self.parent.findings.findings.copy():    # make a copy to avoid searching backups of foundbackups
            self.search_backups(url)

        if not self.parent.findings.backups_urls:
            ptprinthelper.ptprint("No backups found", "NOTVULN", condition=not self.parent.args.json, clear_to_eol=True)

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
        # non_existing_extension_status = self.parent.counters.set_actual_directory_not_found_status(self.parent.scanner.send_request(url + ".qwe").status_code) # get status code for non-existing extensions

        with ThreadPoolExecutor(max_workers=self.parent.args.threads) as executor:
            futures = []
            for backup_char in self.backup_chars:
                futures.append(executor.submit(self.search_for_backup_of_source, url, backup_char, False, True))
                
            for backup_ext in self.backup_exts:
                # Check status for non-existing extension for the current source and add it to --status-code-no
                futures.append(executor.submit(self.search_for_backup_of_source, url, backup_ext, True, False))
                futures.append(executor.submit(self.search_for_backup_of_source, url, backup_ext, False, False))

            for future in as_completed(futures):
                try:
                    if future.result():  # True = backup found
                        self.parent.scanner.process_response(future.result().url, future.result())
                        self.parent.findings.add_to_backups_urls(future.result().url)
                except Exception as e:
                    pass
        return results

    def search_for_backup_of_source(self, url: str, ext: str, old_ext: bool, char_only: bool) -> bool:
        """
        Search for backup versions of a specific source file.
        RUN IN THREADS

        Args:
            url (str): The base file URL.
            ext (str): The backup file extension or delimiter.
            old_ext (bool): Whether to search using the original extension.
            char_only (bool): Whether the ext argument is a delimiter/character only.
        """
        self.parent.counters.increment_counter()
        self.parent.counters.increment_counter_complete()
        url = Url(url).get_url_without_parameters()

        # Dont search for backups for directories or if no extension given or if URL already has backup suffix
        if Url(url).is_url_directory() or has_url_backup_suffix(self, url) or not ext:
                return False

        # Find backups with only special char on the end of URL (http://example.com/index.php~)
        if char_only:
            try:
                url = Url(url).get_url_without_parameters()
                return self.parent.scanner.prepare_and_send_request(url + ext)
            except Exception as e:
                return False

        # Dont remove old extension from URL (http://example.com/index.php.bak)
        if old_ext:
            return self.parent.scanner.prepare_and_send_request(url + ext)
        
        # Remove old extension from URL (http://example.com/index.bak)
        else:
            try:
                url_no_ext = re.sub(r'\.[^./\\]+$', '', url)  # remove last extension
                return self.parent.scanner.prepare_and_send_request(url_no_ext + ext)
            except Exception as e:
                return False


def has_url_backup_suffix(self, url: str) -> bool:
    return url.lower().endswith(tuple(self.backup_exts + self.backup_chars))
