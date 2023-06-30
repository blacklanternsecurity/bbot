import re
from urllib.parse import urljoin

from bbot.modules.base import BaseModule


class git(BaseModule):
    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["active", "safe", "web-basic", "web-thorough"]
    meta = {"description": "Check for exposed .git repositories"}

    in_scope_only = True

    fp_regex = re.compile(r"<html|<body", re.I)

    async def handle_event(self, event):
        base_url = event.data.rstrip("/")
        urls = {
            # git config
            urljoin(base_url, ".git/config"),
            urljoin(f"{base_url}/", ".git/config"),
        }
        tasks = [self.get_url(u) for u in urls]
        for task in self.helpers.as_completed(tasks):
            result, url = await task
            text = getattr(result, "text", "")
            if not text:
                text = ""
            if text:
                if getattr(result, "status_code", 0) == 200 and "[core]" in text and not self.fp_regex.match(text):
                    self.emit_event(
                        {"host": str(event.host), "url": url, "description": f"Exposed .git config at {url}"},
                        "FINDING",
                        event,
                    )

    async def get_url(self, url):
        return (await self.helpers.request(url), url)
