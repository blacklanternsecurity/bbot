from bbot.modules.base import BaseModule


class robots(BaseModule):
    watched_events = ["URL"]
    produced_events = ["URL_UNVERIFIED"]
    flags = ["active", "safe", "web-basic"]
    meta = {"description": "Look for and parse robots.txt", "created_date": "2023-02-01", "author": "@liquidsec"}

    options = {"include_sitemap": False, "include_allow": True, "include_disallow": True}
    options_desc = {
        "include_sitemap": "Include 'sitemap' entries",
        "include_allow": "Include 'Allow' Entries",
        "include_disallow": "Include 'Disallow' Entries",
    }

    in_scope_only = True
    per_hostport_only = True

    async def setup(self):
        return True

    async def handle_event(self, event):
        host = f"{event.parsed_url.scheme}://{event.parsed_url.netloc}/"
        result = None
        url = f"{host}robots.txt"
        result = await self.helpers.request(url)
        if result:
            body = result.text

            if body:
                lines = body.split("\n")
                for l in lines:
                    if len(l) > 0:
                        split_l = l.split(": ")
                        if (split_l[0].lower() == "allow" and self.config.get("include_allow") is True) or (
                            split_l[0].lower() == "disallow" and self.config.get("include_disallow") is True
                        ):
                            unverified_url = f"{host}{split_l[1].lstrip('/')}".replace(
                                "*", self.helpers.rand_string(4)
                            )

                        elif split_l[0].lower() == "sitemap" and self.config.get("include_sitemap") is True:
                            unverified_url = split_l[1]
                        else:
                            continue
                        await self.emit_event(
                            unverified_url,
                            "URL_UNVERIFIED",
                            parent=event,
                            tags=["spider-danger"],
                            context=f"{{module}} found robots.txt at {url} and extracted {{event.type}}: {{event.data}}",
                        )
