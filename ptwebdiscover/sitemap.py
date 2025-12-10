import helpers
from ptlibs import ptprinthelper
import xml.etree.ElementTree as ET

def parse_sitemap(self, url=None, _root_call=True) -> list:
    
    if _root_call:
        ptprinthelper.ptprint("Sitemap crawling:", "TITLE", condition=not self.args.json, clear_to_eol=True)

    if helpers.is_url_domain_only(url):
        url= helpers.get_sitemap_url_from_robots_txt(self, url)

    urls = []
    try:
        r = self.scanner.send_request(url, method="GET")
        r.raise_for_status()
        xml_text = r.content.decode('utf-8-sig')
        root = ET.fromstring(xml_text)
    except Exception as e:
        return []

    # namespace
    ns = {'s': 'http://www.sitemaps.org/schemas/sitemap/0.9'}

    # is sitemap index or regular sitemap
    if root.tag.endswith('sitemapindex'):
        for sitemap in root.findall('s:sitemap', ns):
            loc = sitemap.find('s:loc', ns).text
            urls.extend(parse_sitemap(self, loc, _root_call=False))  # recurse
    else:
        for url_elem in root.findall('s:url', ns):
            loc = url_elem.find('s:loc', ns).text
            urls.append(loc)
    urls = helpers.get_unique_list(urls)
    urls = helpers.filter_urls_by_extension(urls, self.args.extensions)
    urls = helpers.filter_urls_by_domain(urls, self.target.domain)
    return urls
