

from ptlibs import ptnethelper, ptcharsethelper, ptprinthelper, ptjsonlib, ptmisclib
from ptlibs.ptprinthelper import ptprint

from utils.url import Url

from ptdataclasses.findingdetail import FindingDetail
from io import TextIOWrapper


def output_result(args, findings: list[str], findings_details: list[FindingDetail], technologies: list[str]) -> None:
    """
    Output discovered findings and technologies.

    Args:
        findings (list[str]): List of discovered URLs.
        findings_details (list[FindingDetail]): Detailed findings with headers.
        technologies (list[str]): List of detected technologies.
    """

    ptprinthelper.clear_line_ifnot(condition=args.json)
    if findings:
        if args.without_domain:
            domain_with_protocol = Url(args.url).get_domain_from_url(level=True, with_protocol=True)
            findings = [url.replace(domain_with_protocol, "") for url in findings]
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
            #TODO repair JSON
            if args.json:
                print(line)
            if args.output:
                output_file.write(line + "\r\n")
                if args.with_headers:
                    output_file_detail.write(line + "\r\n")
