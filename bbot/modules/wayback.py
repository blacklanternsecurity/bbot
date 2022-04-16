from .base import BaseModule
from urllib.parse import urlparse, quote

# Todo: Add another mode that uses DNS_HOST so that we can find subdomains


class wayback(BaseModule):
    watched_events = ["URL"]
    produced_events = ["URL"]
    scanned_hosts = []

    options = {"include_params": False}
    options_desc = {"include_params": "Include URLs with query strings"}

    def handle_event(self, event):

        dirs = set()
        endpoints = set()
        uris = set()

        parsed_host = urlparse(event.data)
        host = f"{parsed_host.scheme}://{parsed_host.netloc}/"

        if host in self.scanned_hosts:
            self.debug(f"Host {host} was already scanned, exiting")
            return
        else:
            self.scanned_hosts.append(host)

        waybackurl = f"https://web.archive.org/cdx/search/cdx?url={quote(event.data)}&collapse=urlkey&matchType=host&fl=original"
        r = self.helpers.request(waybackurl)
        if not r:
            self.debug(f"Error connecting to archive.org")
            return

        for u in r.text.split("\n"):
            if len(u) > 0:
                u = u.replace(":80", "").replace(":443", "").rstrip()
                if self.helpers.validate_url(u):
                    test_request = self.helpers.request(u, cache_for=3600)
                    if test_request:
                        if test_request.status_code == 200:
                            p = urlparse(u)
                            p._replace(fragment="")._replace(query="")

                            if self.config.get("include_params"):
                                uris.add(p._replace(fragment="").geturl())
                            endpoints.add(p._replace(fragment="", query="").geturl())
                            found_dir = "/".join(p._replace(fragment="", query="").geturl().split("/")[:-1]) + "/"
                            if found_dir != "https://" and found_dir != "http://":
                                dirs.add(found_dir)
                        else:
                            self.debug(f"URL: {u} is not currently accessible, ignoring")

        for dir in dirs:
            self.emit_event(dir, "URL", event, tags=["dir"])

        for endpoint in endpoints:
            self.emit_event(endpoint, "URL", event, tags=["endpoint"])
        if self.config.get("include_params"):
            for uri in uris:
                self.emit_event(uri, "URL", event, tags=["uri"])
