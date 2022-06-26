from .base import BaseModule
from urllib.parse import urlparse, quote

# Todo: Add another mode that uses DNS_HOST so that we can find subdomains


class wayback(BaseModule):
    flags = ["active"]
    watched_events = ["URL"]
    produced_events = ["URL"]
    scanned_hosts = []

    dirs = set()
    endpoints = set()
    uris = set()

    options = {"include_params": True, "skip_potential_large_files": True}
    options_desc = {
        "include_params": "Include URLs with query strings",
        "skip_potential_large_files": "Skips making web requests for file extensions which are potentially very large",
    }

    large_file_extensions = ["zip", "pdf", "avi", "mkv", "avi", "mov", "mp4", "flv", "wmv", "xml"]

    def handle_event(self, event):

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
                    p = urlparse(u)

                    skip_request = False
                    possible_ext = p.path.split(".")[-1]
                    if self.config.get("skip_potential_large_files"):
                        # check if there's an extension that's in the blacklist to avoid downloading huge files

                        if possible_ext in self.large_file_extensions:
                            skip_request = True

                    p._replace(fragment="")._replace(query="")
                    uri = p._replace(fragment="").geturl().rstrip()
                    endpoint = p._replace(fragment="", query="").geturl().rstrip()
                    dir = ("/".join(p._replace(fragment="", query="").geturl().split("/")[:-1]) + "/").rstrip()

                    if self.config.get("include_params"):
                        if uri not in self.uris:
                            self.uris.add(uri)

                            if not skip_request:
                                test_request = self.helpers.request(uri)
                                if test_request:
                                    if (test_request.status_code == 200) or (test_request.status_code == 500):
                                        self.emit_event(uri, "URL", event, tags=["uri"])
                                else:
                                    self.debug(f"URL: {uri} is not currently accessible, ignoring")
                            else:
                                self.warning(
                                    f"Skipping URI {uri} because of extension potentially large extension: [{possible_ext}]"
                                )

                    if endpoint not in self.endpoints:
                        self.endpoints.add(endpoint)
                        test_request = self.helpers.request(endpoint)
                        if not skip_request:
                            if test_request:
                                if (test_request.status_code == 200) or (test_request.status_code == 500):
                                    self.emit_event(endpoint, "URL", event, tags=["endpoint"])
                                else:
                                    self.debug(f"URL: {endpoint} is not currently accessible, ignoring")
                        else:
                            self.warning(
                                f"Skipping URI {uri} because of extension potentially large extension: [{possible_ext}]"
                            )

                    if dir != "https://" and dir != "http://":
                        if dir not in self.dirs:
                            self.dirs.add(dir)
                            test_request = self.helpers.request(u)
                            if test_request:
                                if (
                                    (test_request.status_code == 200)
                                    or (test_request.status_code == 500)
                                    or (test_request.status_code == 403)
                                ):
                                    self.emit_event(dir, "URL", event, tags=["dir"])
                            else:
                                self.debug(f"URL: {dir} is not currently accessible, ignoring")
