from bbot.modules.base import BaseModule
from bbot.core.errors import HttpCompareError

# ([string]method,[string]path,[bool]strip trailing slash)
signatures = []

extensions = [
    ".css",
    ".js",
    ".xls",
    ".png",
    ".jpg",
    ".swf",
    ".xml",
    ".pdf",
    ".gif",
]


# Test for abuse of extension based routing
for ext in extensions:
    signatures.append(("GET", "{scheme}://{netloc}/{path}?foo=%s" % ext, None, True))


class url_manipulation(BaseModule):

    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["active", "aggressive", "web-advanced"]
    meta = {"description": "Attempt to identify URL parsing/routing based vulnerabilities"}
    in_scope_only = True

    def handle_event(self, event):

        try:
            compare_helper = self.helpers.http_compare(event.data, allow_redirects=True)
        except HttpCompareError as e:
            self.debug(e)
            return

        for sig in signatures:

            sig = self.format_signature(sig, event)
            match, reasons, reflection, subject_response = compare_helper.compare(
                sig[1], method=sig[0], allow_redirects=False
            )

            if match == False:
                if str(subject_response.status_code)[0] == "2":

                    if "body" in reasons:
                        reported_signature = f"Modified URL: {sig[1]}"
                        description = f"Url Manipulation: [{','.join(reasons)}] Sig: [{reported_signature}]"
                        self.emit_event(
                            {"description": description, "host": str(event.host), "url": event.data},
                            "FINDING",
                            source=event,
                        )
                else:
                    self.debug(f"Status code changed to {str(subject_response.status_code)}, ignoring")

    def filter_event(self, event):

        accepted_status_codes = ["200", "301", "302"]

        for c in accepted_status_codes:
            if f"status-{c}" in event.tags:
                return True
        return False

    def format_signature(self, sig, event):
        if sig[2] == True:
            cleaned_path = event.parsed.path.strip("/")
        else:
            cleaned_path = event.parsed.path.lstrip("/")

        kwargs = {"scheme": event.parsed.scheme, "netloc": event.parsed.netloc, "path": cleaned_path}
        formatted_url = sig[1].format(**kwargs)
        return (sig[0], formatted_url)
