import re
import helpers
from ptlibs import ptprinthelper
from ptlibs.ptprinthelper import ptprint
from utils import treeshow
from utils.url import Url
from ptdataclasses.findingdetail import FindingDetail
from io import TextIOWrapper


def output_result(args, findings: list[str], findings_details: list[FindingDetail] = [], technologies: list[str] = []) -> None:
    """
    Output the scan results in either tree or list format.
    Result is always printed to console in human-readable format. When JSON output is selected, this function is not called.
    Args:
        args: The command-line arguments.
        findings (list[str]): List of discovered URLs.
        findings_details (list[FindingDetail]): List of detailed findings.
        technologies (list[str]): List of discovered technologies.
    """
    ptprinthelper.clear_line_ifnot(condition=args.json)
    if findings:
        if args.without_domain:
            domain_with_scheme = Url(args.url).get_domain_from_url(level=True, with_protocol=True)
            findings = [url.replace(domain_with_scheme, "") for url in findings]
        ptprinthelper.ptprint( ptprinthelper.out_title_ifnot("Discovered sources", args.json))
        if args.tree:
            output_tree(args, findings)
        else:
            output_list(args, findings, findings_details)
        ptprinthelper.clear_line_ifnot(condition=args.json)
    if technologies:
        ptprinthelper.ptprint( ptprinthelper.out_title_ifnot("Discovered technologies", args.json))
        output_list(args, technologies)
        ptprinthelper.clear_line_ifnot(condition=args.json)

def output_tree(args, line_list: list[str]) -> None:
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
    if args.output:
        output_file = open(args.output,"w+")
        output_file.close()
        tree.save2file(args.output)

def output_list(args, line_list: list[str], line_list_details: list[FindingDetail] = []) -> None:
    """
    Output a list of findings to console and optionally to file.

    Args:
        line_list (list[str]): List of findings.
        line_list_details (list[FindingDetail], optional): Detailed findings.
    """
    line_list = sorted(list(dict.fromkeys(list(line_list))))
    output_file = None
    output_file_detail = None
    if args.output:
        output_file = open(args.output,"w+")
        if args.with_headers:
            output_file_detail = open(args.output+".detail","w+")
    output_lines(args, line_list, line_list_details, output_file, output_file_detail)
    if args.output:
        output_file.close()
        if args.with_headers:
            output_file_detail.close()

def output_lines(args, lines: list[str], line_list_details: list[FindingDetail], output_file: TextIOWrapper, output_file_detail: TextIOWrapper) -> None:
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
        if args.with_headers:
            for line_detail in line_list_details:
                if line_detail.url == line:
                    is_detail = True
                    ptprinthelper.ptprint( ptprinthelper.out_ifnot("[" + str(line_detail.status_code) + "]  " + line + "\n", condition=args.json), end="")
                    if args.output:
                        output_file_detail.write("[" + str(line_detail.status_code) + "]  " + line + "\r\n")
                    try:
                        for key, value in line_detail.headers.items():
                            if args.output:
                                output_file_detail.write(" " * 7 + key + " : " + value + "\r\n")
                            ptprinthelper.ptprint( ptprinthelper.out_ifnot(" " * 7 + key + " : " + value, "ADDITIONS", condition=args.json, colortext=True))
                        break
                    except:
                        pass
            ptprinthelper.ptprint( ptprinthelper.out_ifnot("\n", condition=args.json))
            
        if not is_detail:
            ptprinthelper.ptprint( ptprinthelper.out_ifnot(line, condition=args.json))

            # Write to output file if specified
            if args.output:
                output_file.write(line + "\r\n")
                if args.with_headers:
                    output_file_detail.write(line + "\r\n")


def print_results(self):
    """
    Print or export the final scan results.

    Outputs discovered URLs, details, and technologies in either human-readable
    or JSON format.
    """

    # Add vulnerabilities to JSON if specified in arguments -vuln-yes or -vuln-no
    # Backups
    if self.args.backups:
        if self.findings.backups_urls and self.args.vuln_yes:
            self.ptjsonlib.add_vulnerability(self.args.vuln_yes)
        if not self.findings.backups_urls and self.args.vuln_no:
            self.ptjsonlib.add_vulnerability(self.args.vuln_no)
    # Findings
    else:
        if len(self.findings.findings) > 1 and self.args.vuln_yes:  # more than only root directory
            self.ptjsonlib.add_vulnerability(self.args.vuln_yes)
        if len(self.findings.findings) < 2 and self.args.vuln_no:
            self.ptjsonlib.add_vulnerability(self.args.vuln_no)

    # Only URLs by extensions specified in --extensions_output will be printed
    if self.args.extensions_output:
        self.findings.findings = helpers.filter_urls_by_extension(self.findings.findings, self.args.extensions_output)

    # Output results in JSON or human-readable format
    if self.args.json:
        nodes: list = self.ptjsonlib.parse_urls2nodes(self.findings.findings)
        self.ptjsonlib.add_nodes(nodes)
        self.ptjsonlib.set_status("finished")
        ptprinthelper.ptprint(self.ptjsonlib.get_result_json(), "", self.args.json)
    else:
        output_result(self.args, self.findings.findings, self.findings.details, self.findings.technologies)

    # Print foreign domain URLs if the option is enabled
    if self.args.foreign_domains:
        if self.findings.foreign_domain_urls:
            ptprinthelper.ptprint( ptprinthelper.out_title_ifnot("Foreign domain URLs found", self.args.json), newline_above=True)
            for url in self.findings.foreign_domain_urls:
                ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"{url}", "", self.args.json))

def print_warnings(self) -> None:
    if self.findings.directory_listing_urls or self.findings.long_content_in_redirect_urls or self.findings.backups_urls:
        ptprinthelper.ptprint( ptprinthelper.out_ifnot("Warning: Next potential problems found:", "WARNING", condition=self.args.json, colortext=True))
        if self.findings.directory_listing_urls:
            ptprinthelper.ptprint( ptprinthelper.out_ifnot("Directory listing found at:", "WARNING", self.args.json), newline_above=True)
            for url in self.findings.directory_listing_urls:
                ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"    {url}", "", self.args.json))
        if self.findings.long_content_in_redirect_urls:
            ptprinthelper.ptprint( ptprinthelper.out_ifnot("Long content found in redirects at:", "WARNING", self.args.json), newline_above=True)
            for url in self.findings.long_content_in_redirect_urls:
                ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"    {url}", "", self.args.json))
        if self.findings.backups_urls:
            ptprinthelper.ptprint( ptprinthelper.out_ifnot("Backups found at:", "WARNING", self.args.json), newline_above=True)
            for url in self.findings.backups_urls:
                ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"    {url}", "", self.args.json))

def print_finish_message(self) -> None:
    ptprinthelper.ptprint( ptprinthelper.out_ifnot(f"Finished in {self.counters.get_elapsed_time()} - discovered: {len(self.findings.findings)} items", "INFO", self.args.json), newline_above=True)