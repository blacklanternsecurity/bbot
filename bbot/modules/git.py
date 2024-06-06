import re

from bbot.modules.base import BaseModule


class git(BaseModule):
    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["active", "safe", "web-basic", "web-thorough"]
    meta = {
        "description": "Check for exposed .git repositories",
        "created_date": "2023-05-30",
        "author": "@TheTechromancer",
    }

    in_scope_only = True

    fp_regex = re.compile(r"<html|<body", re.I)

    async def handle_event(self, event):
        base_url = event.data.rstrip("/")
        urls = {
            # look for git config in both
            self.helpers.urljoin(base_url, ".git/config"),
            self.helpers.urljoin(f"{base_url}/", ".git/config"),
        }
        tasks = [self.get_url(u) for u in urls]
        async for task in self.helpers.as_completed(tasks):
            result, url = await task
            text = getattr(result, "text", "")
            if not text:
                text = ""
            if text:
                if getattr(result, "status_code", 0) == 200 and "[core]" in text and not self.fp_regex.match(text):
                    await self.emit_event(
                        {"host": str(event.host), "url": url, "description": f"Exposed .git config at {url}"},
                        "FINDING",
                        event,
                    )

    async def get_url(self, url):
        return (await self.helpers.request(url), url)
