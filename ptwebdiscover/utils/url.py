import os

import tldextract
import urllib.parse


class Url:
    
    def __init__(self, url: str) -> None:
        self.url = url


    def get_path_from_url(self, with_l_slash=True, without_r_slash=False) -> str:
        url = self.get_url_without_parameters()
        out_r_slash = -1 if self.is_url_dictionary() and without_r_slash else None
        url = url.replace("//", "::")
        domain_len = url.find("/") if url.find("/")>0 else len(url)
        if with_l_slash:
            return url[domain_len:out_r_slash]
        else:
            return url[domain_len+1:out_r_slash]
        
        
    def get_url_without_parameters(self) -> str:
        return self.url.split("?")[0].split("#")[0]
    
    
    def is_url_dictionary(self):
        return self.get_url_without_parameters().endswith("/")
    
    
    def standardize_url(self, domain_with_protocol: str) -> str:
        path = self.url[len(domain_with_protocol):]
        if not path.startswith("/"):
            path = "/"
        abs = os.path.abspath(path)+"/" if path.endswith("/") and path !="/" else os.path.abspath(path)
        return domain_with_protocol + abs
    
    
    def get_domain_from_url(self, level=True, with_protocol=True) -> str:
        subdom, dom, suf = tldextract.extract(self.url)
        if subdom: 
            subdom += "."
        if with_protocol:
            protocol = self.url.split("://")[0] + "://" if "://" in self.url else "http://"
        else:
            protocol = "" 
        if level:
            return protocol + subdom + dom + ("." if suf else "") + suf
        else:
            return protocol + dom + ("." if suf else "") + suf
        
        
    def add_missing_scheme(self, scheme: str) -> str:
        extract = urllib.parse.urlparse(self.url)
        if self.url and not (extract.scheme):
            return scheme + "://" + self.url
        else:
            return self.url