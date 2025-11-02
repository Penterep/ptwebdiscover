import os
import re
import requests
from ptlibs import ptprinthelper
from ptwebdiscover import helpers
from utils.url import Url
from ptdataclasses.findingdetail import FindingDetail


class ResponseProcessor:

    def __init__(self, parent) -> None:
        self.parent = parent

    def save_content(self, content: bytes, path: str, save_path: str) -> None:
        path = save_path + "/" + path
        dirname = os.path.dirname(path)
        if self.is_directory_traversal(path, save_path):
            return
        os.makedirs(dirname, exist_ok=True)
        if dirname + "/" != path:
            output_file = open(path,"wb")
            output_file.write(content)
            output_file.close()


    def is_directory_traversal(self, path: str, save_path: str) -> bool:
        current_directory = os.path.abspath(save_path)
        requested_path = os.path.abspath(path)
        common_prefix = os.path.commonprefix([requested_path, current_directory])
        return common_prefix != current_directory


    def get_text_directory_or_file(self, response: requests.Response, request_url: str) -> tuple[str,str]:
        if response.url == request_url + "/" or Url(response.url).is_url_directory():
            if response.status_code == 200:
                if self.parent.args.method.upper() == "HEAD":
                    response = self.parent.scanner.send_request(response.url, method="GET", headers=self.parent.args.headers, timeout=self.parent.args.timeout, proxies=self.parent.args.proxies, verify=False, redirects=True, cache=self.parent.args.cache)
                if "Index of" in response.text: # Directory listing found
                    self.parent.findings.add_to_directory_listing_urls(response.url)
                    return "directory", "[" + ptprinthelper.get_colored_text("D", "ERROR") + "] "
                else:
                    return "directory", "[D] "
            else:
                return "directory", "[D] "
        else:
            return "file", "[F] "


    def get_response_history(self, history: list[requests.Response]) -> str:
        output = ""
        for response in history:

            r = "R"
            # If long content in redirect maybe interesting
            if response.is_redirect and len(response.text) > 500:
                self.parent.findings.add_to_long_content_in_redirect_urls(response.url)
                r = ptprinthelper.get_colored_text("R", "ERROR")
            string = ptprinthelper.out_ifnot(f"[{response.status_code}] [{r}]  {response.url}  \u2794", "REDIR", self.parent.args.json)
            output += ptprinthelper.add_spaces_to_eon(string) + "\n"
            self.parse_url_and_add_unique_url_and_directories(response.url, response)
            output += self.get_content_location(response)

        return output


    def parse_url_and_add_unique_url_and_directories(self, url: str, response: requests.Response = None) -> None:
        url_with_params = url
        url_object = Url(url)
        if url_object.get_domain_from_url(with_protocol=False) != self.parent.target.domain:
            return
        if not self.parent.args.include_parameters:
            url = url_object.get_url_without_parameters()
        path_from_url = url_object.get_path_from_url()
        segmented_path = [i for i in path_from_url.split("/")]
        last_segment_no = len(segmented_path) - 1 # because for loop starts from 0 is set -1
        is_dir = url_object.is_url_directory()
        path = "/"
        for i, segment in enumerate(segmented_path):
            path += segment
            url = self.parent.target.domain_with_scheme + path
            if (i != last_segment_no or (i==last_segment_no and is_dir)) and not self.parent.target.url.endswith(path):
                # Add directory
                self.add_unique_finding_to_findings(url + "/", response if self.is_response(response) else None)
                path += "/" if not path.endswith("/") else ""
                self.add_unique_directory_to_directories(path)
                if i == last_segment_no-1 and self.is_response(response):
                    finding_detail = FindingDetail(url=url, status_code=response.status_code, headers=response.headers)
                    self.parent.findings.details.append(finding_detail)
            else:
                # Add file
                if (i == last_segment_no and self.parent.args.include_parameters):
                    url = url_with_params   # Keep parameters in last segment (file)
                self.add_unique_finding_to_findings(url, response if self.is_response(response) else None)
                path += "/"


    def add_unique_finding_to_findings(self, url: str, response: requests.Response=None) -> None:
        url = url.replace("//", "/")
        url = url.replace(":/", "://")
        url = Url(url).standardize_url(self.parent.target.domain_with_scheme)
        
        if self.parent.args.is_star_in_domain:
            url = response.url

        if Url(url).is_url_directory() and url[:-1] in self.parent.findings.findings:
            self.parent.findings.findings.remove(url[:-1])

        if not url in self.parent.findings.findings and not url+"/" in self.parent.findings.findings:
            url = helpers.normalize_url(url)
            self.parent.findings.add_to_findings(url)
            if self.is_response(response):
                findingDetail = FindingDetail(url=url, status_code=response.status_code, headers=response.headers)
                self.parent.findings.details.append(findingDetail)


    def is_response(self, response: requests.Response) -> bool:
        try:
            return True if response.status_code else False
        except:
            return False


    def add_unique_directory_to_directories(self, directory: str) -> None:
        directory = os.path.abspath(directory)
        directory = directory + "/" if directory != "/" else directory
        if self.parent.args.recurse and directory.count('/') > self.parent.args.max_depth+1:
            return
        if not directory in self.parent.findings.directories and self.parent.args.recurse and directory.startswith(self.parent.target.path) and not self.started_path_with(directory, self.parent.args.not_directories):
            self.parent.findings.directories.append(directory)
            self.parent.counters.increment_keyspace_complete_by(self.parent.counters.get_keyspace())


    def started_path_with(self, directory: str, not_directories: list[str]) -> bool:
        for nd in not_directories:
            if directory.startswith(nd):
                return True
        return False


    def get_content_location(self, response: requests.Response) -> str:
        output = ""
        try:
            if response.headers['Content-Location']:
                content_location = self.get_string_before_last_char(response.url, "/") + "/" +response.headers['Content-Location']
                string = ptprinthelper.out_ifnot(f"[-->] [L]  {content_location}", "OK", self.parent.args.json)
                output += ptprinthelper.add_spaces_to_eon(string)
                self.parse_url_and_add_unique_url_and_directories(content_location, response)
        except:
            pass
        return output


    def get_string_before_last_char(self, string: str, chars: list[str]) -> str:
        for char in chars:
            string = string.rpartition(char)[0]
        return string


    def parse_html_find_and_add_urls(self, response: requests.Response) -> str:
        output = "\n"
        urls = self.find_urls_in_html(response, self.parent.target.scheme)
        for url in urls:
            string = ptprinthelper.out_ifnot(f"           {url}", "PARSED", self.parent.args.json)
            output += ptprinthelper.add_spaces_to_eon(string) + "\n"
            self.parse_url_and_add_unique_url_and_directories(url, response)
        return output.rstrip()


    def find_urls_in_html(self, response: requests.Response, domain_protocol: str) -> list[str]:
        urls = helpers.get_all_urls_from_response(response)
        rel_paths, foreign_urls = helpers.get_all_urls_from_mixed_url_list(self, urls, domain=self.parent.target.domain, keep_params=self.parent.args.include_parameters)
        rel_paths = helpers.normalize_urls(self,rel_paths)
        self.parent.findings.add_to_foreign_domain_urls(foreign_urls)   #Add foreign URLs to array of foreign URLs
        return list(dict.fromkeys(list(rel_paths)))

    def get_last_parsed_character_index(self, response: requests.Response) -> int:
        last_parsed_character = self.parent.args.content_length / self.get_encoding_bytes_per_char(response.encoding)
        return int(last_parsed_character)


    def get_encoding_bytes_per_char(self, encoding: str) -> int:
        char = "A"
        encoded_bytes = char.encode(encoding)
        return len(encoded_bytes)

    def get_content_type_and_length(self, headers: dict[str,str]) -> tuple[str, str]:
        try:
            c_l = headers['content-length']
        except:
            c_l = "?"
        try:
            c_t = headers['Content-Type'].split(";")[0]
        except:
            c_t = "unknown"
        return c_t, c_l


    def add_unique_technology_to_technologies(self, technology: str) -> None:
        if not technology in self.parent.findings.technologies:
            self.parent.findings.technologies.append(technology)


    def content_shorter_than_maximum(self, response: requests.Response) -> bool:
        _, c_l = self.get_content_type_and_length(response.headers)
        if not c_l.isdigit():
            return False

        content_length = int(c_l)
        return content_length < self.args.content_length