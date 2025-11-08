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

import sys; sys.path.append(__file__.rsplit("/", 1)[0])
import requests
import scanner
import helpers
import results
import webarchive

from ptlibs import ptjsonlib, ptprinthelper
from ptlibs.threads import ptthreads, printlock, arraylock
from backups import Backups

from ptdataclasses.argumentoptions import ArgumentOptions

from utils import args_processing
from findings import Findings
from counters import Counters
from target import Target

class PtWebDiscover():

    def __init__(self, args: ArgumentOptions) -> None:
        self.args                            = args
        self.ptjsonlib                       = ptjsonlib.PtJsonLib()
        self.ptthreads                       = ptthreads.PtThreads()
        self.printlock                       = printlock.PrintLock()
        self.arraylock                       = arraylock.ArrayLock()
        self.scanner                         = scanner.Scanner(self)
        self.findings                        = Findings()
        self.findings.forbidden_paths        = args.forbidden_paths
        self.counters                        = Counters()
        self.target                          = Target()
        self.target.url                      = args.url if not args.url.endswith("/") else args.url[:-1]    # https://www.example.com/index.php
        self.target.domain                   = args.domain                                                  # www.example.com
        self.target.domain_with_scheme       = args.domain_with_scheme                                      # https://www.example.com
        self.target.path                     = args.path                                                    # /index.php
        self.target.scheme                   = args.scheme                                                  # http or https
        self.target.port                     = args.port                                                    # 80, 443, or custom port

    def run(self) -> None:
        payloads = [""]
        if self.args.archive:
            url_list, payloads = webarchive.get_urls_from_webarchive(self) # returns url_list (full URLs), payloads (only paths)
            if not "checked" in str(self.args.archive):
                self.findings.findings.extend(url_list)
                results.print_results(self)
                results.print_finish_message(self)
                return
            results.output_result(self.args, url_list)
            ptprinthelper.ptprint(f"Webarchive URLs: {len(payloads)}\n", "INFO", condition=not self.args.json, clear_to_eol=True)

        payloads, keyspace = helpers.prepare_payloads(self, payloads)
        self.counters.set_keyspace(keyspace)
        self.counters.set_keyspace_complete(self.counters.get_keyspace())

        helpers.print_configuration(self)
        helpers.check_website_and_method_availability(self)

        if self.args.non_exist:
            self.scanner.test_status_for_non_existing_resource(self.target.url)
            # Exit after testing non-existing resource
            return

        if self.args.extensions_whitelist:
            self.scanner.check_extensions_whitelisting()
            # Exit after testing non-existing resource
            return

        self.findings.directories = helpers.get_initial_directories(self)

        while self.findings.directories:
            self.scanner.main_searching(self.findings.directories, payloads)

            if self.args.recurse:
                if self.args.parse:
                    self.scanner.process_notvisited_urls()
            else:
                break

        if self.args.backups and not self.args.backup_all:
            backups = Backups(self)
            backups.process_backups()

        results.print_results(self)
        results.print_warnings(self)
        results.print_finish_message(self)


def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptwebdiscover"
    requests.packages.urllib3.disable_warnings()
    args = args_processing.parse_args(SCRIPTNAME)
    script = PtWebDiscover(args)
    script.run()


if __name__ == "__main__":
    main()
