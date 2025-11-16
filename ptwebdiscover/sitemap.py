import helpers
import xml.etree.ElementTree as ET

def parse_sitemap(self, url=None) -> list:
    urls = []
    try:
        r = self.scanner.send_request(url, method="GET")
        r.raise_for_status()
        xml_text = r.content.decode('utf-8-sig')
        root = ET.fromstring(xml_text)
    except Exception as e:
        input(f"Error parsing sitemap {url}: {e}")
        return []

    # namespace
    ns = {'s': 'http://www.sitemaps.org/schemas/sitemap/0.9'}

    # is sitemap index or regular sitemap
    if root.tag.endswith('sitemapindex'):
        for sitemap in root.findall('s:sitemap', ns):
            loc = sitemap.find('s:loc', ns).text
            urls.extend(parse_sitemap(self, loc))  # recurse
    else:
        for url_elem in root.findall('s:url', ns):
            loc = url_elem.find('s:loc', ns).text
            urls.append(loc)
    print(f"Found {len(urls)} URLs in sitemap: {url}\n")
    urls = helpers.get_unique_list(urls)
    urls = helpers.filter_urls_by_extension(urls, self.args.extensions)
    urls = helpers.filter_urls_by_domain(urls, self.target.domain)
    return urls
