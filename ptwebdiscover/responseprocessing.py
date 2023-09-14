import os
import re
import requests

import ptlibs.ptprinthelper as ptprinthelper
from keyspace import Keyspace

from ptdataclasses.processedargumentoptions import ProcessedArgumentOptions
from utils.url import Url
from findings import FindingDetail, Findings

class ResponseProcessor:
    
    def __init__(self, domain_with_protocol: str, domain: str, args: ProcessedArgumentOptions) -> None:
        self.domain_with_protocol = domain_with_protocol
        self.domain = domain
        self.args = args
    
    
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
    
        
    def check_content_type(self, response: requests.Response, request_url: str) -> tuple[str,str]:
        if response.url == request_url + "/" or Url(response.url).is_url_dictionary():
            if response.status_code == 200:
                return "directory", "[" + ptprinthelper.get_colored_text("D", "ERROR") + "] "
            else:
                return "directory", "[D] "
        else:
            return "file", "[F] "
        
        
    def get_response_history(self, history: list[requests.Response], json: bool, include_parameters: bool, urlpath: str, keyspace_for_directory: int) -> str:
        output = ""
        for resp in history:
            string = ptprinthelper.out_ifnot(f"[{resp.status_code}] [R]  {resp.url}  \u2794", "REDIR", json)
            output += ptprinthelper.add_spaces_to_eon(string) + "\n"
            self.parse_url_and_add_unigue_url_and_directories(resp.url, include_parameters, urlpath, keyspace_for_directory, resp)
            output += self.get_content_location(include_parameters, urlpath, keyspace_for_directory ,resp)
        return output
    
    
    def parse_url_and_add_unigue_url_and_directories(self, url: str, include_parameters: bool, urlpath: str, keyspace_for_directory: int, response: requests.Response = None) -> None:
        url_object = Url(url)
        if not include_parameters:
            url = url_object.get_url_without_parameters()
        path_from_url = url_object.get_path_from_url()
        segmented_path = [i for i in path_from_url.split("/")]
        last_segment_no = len(segmented_path)
        is_dir = url_object.is_url_dictionary()
        path = "/"
        for i, segment in enumerate(segmented_path):
            path += segment
            if (i != last_segment_no-1 or (i==last_segment_no-1 and is_dir)) and not self.args.url.endswith(path):
                self.add_unique_finding_to_findings(self.domain_with_protocol + path + "/", response if self.is_response(response) else None, urlpath)
                path += "/"
                path = re.sub('/{2,}', "/", path)
                self.add_unigue_directory_to_directories(path, urlpath, keyspace_for_directory)
                if i == last_segment_no-1 and self.is_response(response):
                    finding_detail = FindingDetail(url=self.domain_with_protocol + path, status_code=response.status_code, headers=response.headers)
                    Findings.details.append(finding_detail)
            else:
                self.add_unique_finding_to_findings(self.domain_with_protocol + path, response if self.is_response(response) else None, urlpath)
                path += "/"
                
    
    def add_unique_finding_to_findings(self, url: str, response: requests.Response, urlpath: str) -> None:
        url = url.replace("//", "/")
        url = url.replace(":/", "://")
        url = Url(url).standardize_url(self.domain_with_protocol)
        if self.args.is_star_in_domain:
            url = response.url
        if Url(url).is_url_dictionary() and url[:-1] in Findings.findings:
            Findings.findings.remove(url[:-1])
        if not url in Findings.findings and not url+"/" in Findings.findings and (Url(url).get_path_from_url().startswith(urlpath) or self.args.is_star_in_domain):
            Findings.findings.append(url)
            if self.is_response(response):
                findingDetail = FindingDetail(url=url, status_code=response.status_code, headers=response.headers)
                Findings.details.append(findingDetail)
            if self.args.backups and self.is_response(response) and not str(response.status_code).startswith("4"):
                Findings.findings2.append(url)
                Keyspace.increment_space()
                Keyspace.increment_space_complete()
            if self.args.parse:
                Keyspace.increment_space_complete()
                
    
    def is_response(self, response: requests.Response) -> bool:
        try:
            return True if response.status_code else False
        except:
            return False
        
        
    def add_unigue_directory_to_directories(self, directory: str, urlpath: str, keyspace_for_directory: int) -> None:
        directory = os.path.abspath(directory)
        directory = directory + "/" if directory != "/" else directory
        if self.args.recurse and directory.count('/') > self.args.max_depth+1:
            return
        if not directory in Findings.directories and self.args.recurse and directory.startswith(urlpath) and not self.started_path_with(directory, self.args.not_directories):
            Findings.directories.append(directory)
            Keyspace.increment_space_complete_by(keyspace_for_directory)
            
            
    def started_path_with(self, directory: str, not_directories: list[str]) -> bool:
        for nd in not_directories:
            if directory.startswith(nd):
                return True
        return False
    
    
    def get_content_location(self, include_parameters: bool, urlpath: str, keyspace_for_directory: int, response: requests.Response) -> str:
        output = ""
        try:
            if response.headers['Content-Location']:
                content_location = self.get_string_before_last_char(response.url, "/") + "/" +response.headers['Content-Location']
                string = ptprinthelper.out_ifnot(f"[-->] [L]  {content_location}", "OK", self.args.json)
            output += ptprinthelper.add_spaces_to_eon(string)
            self.parse_url_and_add_unigue_url_and_directories(content_location, include_parameters, urlpath, keyspace_for_directory, response)
        except:
            pass
        return output
    
    
    def get_string_before_last_char(self, string: str, chars: list[str]) -> str:
        for char in chars:
            string = string.rpartition(char)[0]
        return string
    
    
    def parse_html_find_and_add_urls(self, response: requests.Response, include_parameters: bool, urlpath: str, keyspace_for_directory: int, domain_protocol: str) -> str:
        if self.args.parse:
            output = "\n"
            urls = self.find_urls_in_html(response, domain_protocol)
            for url in urls:
                string = ptprinthelper.out_ifnot(f"           {url}", "PARSED", self.args.json)
                output += ptprinthelper.add_spaces_to_eon(string) + "\n"
                self.parse_url_and_add_unigue_url_and_directories(url, include_parameters, urlpath, keyspace_for_directory)
            return output.rstrip()
        else:
            return ""
        
        
    def find_urls_in_html(self, response: requests.Response, domain_protocol: str) -> list[str]:
        page_content = response.text
        if self.args.include_parameters:
            absolute_url_patern = re.compile(r'(https?)(:\/\/' + self.domain.replace(".", "\\.") + ')(\/?[^\[\]\'"><\s]*)?[\'"><\s]', flags=re.IGNORECASE)
            relative_url_patern = re.compile(r'(sitemap: |allow: | href=[\'"]*| src=[\'"]*)([^\[\]\\\'"\s<>]*)', flags=re.IGNORECASE)
        else:
            absolute_url_patern = re.compile(r'(https?)(:\/\/' + self.domain.replace(".", "\\.") + ')(\/[^\[\]\'"><?#\s]*)?[\'">?#<\s]', flags=re.IGNORECASE)
            relative_url_patern = re.compile(r'(sitemap: |allow: | href=[\'"]*| src=[\'"]*)([^\[\]\\\'"?#\s<>]*)', flags=re.IGNORECASE)
        max_parsed_content_length = self.get_last_parsed_character_index(response)
        all_urls = list({''.join(result) for result in absolute_url_patern.findall(page_content, endpos=max_parsed_content_length)})
        all_rel_urls = list({result[1] for result in relative_url_patern.findall(page_content, endpos=max_parsed_content_length)})
        for url in all_rel_urls:
            if not url in ["", "/", "?", "#"] and not url.lower().startswith(("mailto:", "tel:", "news:", "ftp:", "ftps:", "data:", "javascript:", "vbscript:")):
                absurl = self.rel2abs(response.url, url, domain_protocol)
                if absurl:
                    all_urls.append(absurl)
        return list(dict.fromkeys(list(all_urls)))
    
    
    def get_last_parsed_character_index(self, response: requests.Response) -> int:
        last_parsed_character = self.args.content_length / self.get_encoding_bytes_per_char(response.encoding)
        return int(last_parsed_character)
    
    
    def get_encoding_bytes_per_char(self, encoding: str) -> int:
        char = "A"
        encoded_bytes = char.encode(encoding)
        return len(encoded_bytes)
    
    
    def rel2abs(self, location: str, url: str, domain_protocol: str) -> str:
        if re.match('^\w{2,5}:\/\/', url):
            if re.match('^\w{2,5}:\/\/' + self.domain.replace(".", "\\."), url):
                return url
            else:
                return None
        elif url.startswith("//"):
            if url.startswith("//" + self.domain):
                return domain_protocol + url
            else:
                return None
        elif url.startswith("/"):
            return self.domain_with_protocol + url
        else: 
            if url.startswith("?") or url.startswith("#"):
                return self.get_string_before_last_char(location, ["?", "#"]) + url
            else:
                return self.get_string_before_last_char(location, ["/"]) + "/" + url
            
            
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
        
        
    def add_unigue_technology_to_technologies(self, technology: str) -> None:
        if not technology in Findings.technologies:
            Findings.technologies.append(technology)
            
    
    def content_shorter_than_maximum(self, response: requests.Response) -> bool:
        _, c_l = self.get_content_type_and_length(response.headers)
        if not c_l.isdigit():
            return False
        
        content_length = int(c_l)
        return content_length < self.args.content_length