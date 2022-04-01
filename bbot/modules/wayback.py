from .base import BaseModule
from urllib.parse import urlparse, quote


# Todo: Change query so that we can find subdomains


class wayback(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["URL"]

    def handle_event(self, event):

        dirs = set()
        endpoints = set()
        uris = set()

        waybackurl = f"https://web.archive.org/cdx/search/cdx?url={quote(event.data)}&collapse=urlkey&matchType=host&fl=original"
        r = self.helpers.request(waybackurl)
        if not r:
            self.debug(f"Error connecting to archive.org")
            return

        for u in r.text.split("\n"):
            if len(u) > 0:

                if self.helpers.validate_url(u):

                    p = urlparse(u)
                    p._replace(fragment="")._replace(query="")

                    uris.add(p._replace(fragment="").geturl())
                    endpoints.add(p._replace(fragment="", query="").geturl())
                    dirs.add(
                        "/".join(
                            p._replace(fragment="", query="").geturl().split("/")[:-1]
                        )
                        + "/"
                    )

        for dir in dirs:
            self.emit_event(dir, "URL", event, tags=["dir"])

        for endpoint in endpoints:
            self.emit_event(endpoint, "URL", event, tags=["endpoint"])

        for uri in uris:
            self.emit_event(uri, "URL", event, tags=["uri"])
