from findings import Findings
from keyspace import Keyspace


class BackupsDiscovery:
    def __init__(self, args, ptjsonlib):
        self.args = args
        self.ptjsonlib = ptjsonlib

        self.prepare_backup()

    def process_all_backups(self):
        """
        Search for complete backups of the entire target website.
        """
        #self.prepare_backup()
        self.search_for_backup_of_all(self.domain)


    def process_backups(self) -> None:
        """
        Search for possible backup files in discovered resources.
        """
        Findings.findings2 = Findings.findings.copy()
        #self.prepare_backup()
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
        if self.args.backup_all:
            total_extensions = list(set(self.backup_exts + self.backup_all_exts))
            Keyspace.space = len(total_extensions) * 5
            #Keyspace.space = (len(self.backup_exts) + len(self.backup_all_exts) + len(self.delimeters) + len(self.backup_chars) + len(self.wordlist)) * 5
            #len(self.extensions)

        Keyspace.increment_space_complete_by(Keyspace.space)


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