import time
from ptlibs import ptprinthelper

def get_all_urls(self):

    ptprinthelper.ptprint("Google Custom Search crawling:", "TITLE", condition=not self.args.json, clear_to_eol=True)

    all_urls = set()

    extensions = self.args.extensions if self.args.extensions != [''] else []

    # ✅ if not extensions → one query without filetype
    if not extensions:
        query_parts = [f"site:{self.target.domain}"]

        if self.args.string_in_response:
            query_parts.append(f'"{self.args.string_in_response}"')

        if self.args.string_not_in_response:
            query_parts.append(f'-"{self.args.string_not_in_response}"')

        query = " ".join(query_parts)
        ptprinthelper.ptprint(f"Query: {query}", "INFO", condition=not self.args.json)

        run_google_query(self, query, all_urls)

    # ✅ if extensions → one query for each extension
    else:
        for ext in extensions:
            query_parts = [
                f"site:{self.target.domain}",
                f"filetype:{ext.lower().lstrip('.')}"
            ]

            if self.args.string_in_response:
                query_parts.append(f'"{self.args.string_in_response}"')

            if self.args.string_not_in_response:
                query_parts.append(f'-"{self.args.string_not_in_response}"')

            query = " ".join(query_parts)
            ptprinthelper.ptprint(f"Query: {query}", "INFO", condition=not self.args.json)

            run_google_query(self, query, all_urls)

    return list(all_urls)

def run_google_query(self, query, all_urls):
    start = 1

    while start <= 100:
        data = google_search(self, query, self.args.google_api, self.args.google_cx, start=start)

        if not data or "items" not in data:
            break

        for item in data["items"]:
            all_urls.add(item["link"])

        start += 10
        time.sleep(1)

def google_search(self, query, api_key, cx, start=1):
    url = f"https://www.googleapis.com/customsearch/v1?key={api_key}&cx={cx}&q={query}&start={start}"
    try:
        response = self.scanner.send_request(url, method="GET")
        response.raise_for_status()
        return response.json()
    except Exception as e:
        ptprinthelper.ptprint(f"Error during Google Custom Search API request: {e}", "ERROR", condition=not self.args.json)
        return {}