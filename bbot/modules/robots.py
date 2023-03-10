from bbot.modules.base import BaseModule


class robots(BaseModule):
    watched_events = ["URL"]
    produced_events = ["URL_UNVERIFIED"]
    flags = ["active", "safe", "web-basic", "web-thorough"]
    meta = {"description": "Look for and parse robots.txt"}

    options = {"include_sitemap": False, "include_allow": True, "include_disallow": True}
    options_desc = {
        "include_sitemap": "Include 'sitemap' entries",
        "include_allow": "Include 'Allow' Entries",
        "include_disallow": "Include 'Disallow' Entries",
    }

    in_scope_only = True

    def setup(self):
        self.scanned_hosts = set()
        return True

    def handle_event(self, event):
        parsed_host = event.parsed
        host = f"{parsed_host.scheme}://{parsed_host.netloc}/"
        host_hash = hash(host)
        if host_hash in self.scanned_hosts:
            self.debug(f"Host {host} was already scanned, exiting")
            return
        else:
            self.scanned_hosts.add(host_hash)

        result = None
        url = f"{host}robots.txt"
        result = self.helpers.request(url)
        if result:
            body = result.text

            if body:
                lines = body.split("\n")
                for l in lines:
                    if len(l) > 0:
                        split_l = l.split(": ")
                        if (split_l[0].lower() == "allow" and self.config.get("include_allow") == True) or (
                            split_l[0].lower() == "disallow" and self.config.get("include_disallow") == True
                        ):
                            unverified_url = f"{host}{split_l[1].lstrip('/')}".replace(
                                "*", self.helpers.rand_string(4)
                            )

                        elif split_l[0].lower() == "sitemap" and self.config.get("include_sitemap") == True:
                            unverified_url = split_l[1]
                        else:
                            continue

                        self.emit_event(unverified_url, "URL_UNVERIFIED", source=event)
