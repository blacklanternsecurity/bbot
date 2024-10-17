import re
from bbot.modules.base import BaseModule


class code_repository(BaseModule):
    watched_events = ["URL_UNVERIFIED"]
    produced_events = ["CODE_REPOSITORY"]
    meta = {
        "description": "Look for code repository links in webpages",
        "created_date": "2024-05-15",
        "author": "@domwhewell-sage",
    }
    flags = ["passive", "safe", "code-enum"]

    # platform name : (regex, case_sensitive)
    code_repositories = {
        "git": [
            (r"github.com/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+", False),
            (r"gitlab.(?:com|org)/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+", False),
        ],
        "docker": (r"hub.docker.com/r/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+", False),
        "postman": (r"www.postman.com/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+", False),
    }

    scope_distance_modifier = 1

    async def setup(self):
        self.compiled_regexes = {}
        for k, v in self.code_repositories.items():
            if isinstance(v, list):
                self.compiled_regexes[k] = [(re.compile(pattern), c) for pattern, c in v]
            else:
                pattern, c = v
                self.compiled_regexes[k] = (re.compile(pattern), c)
        return True

    async def handle_event(self, event):
        for platform, regexes in self.compiled_regexes.items():
            if not isinstance(regexes, list):
                regexes = [regexes]
            for regex, case_sensitive in regexes:
                for match in regex.finditer(event.data):
                    url = match.group()
                    if not case_sensitive:
                        url = url.lower()
                    url = f"https://{url}"
                    repo_event = self.make_event(
                        {"url": url},
                        "CODE_REPOSITORY",
                        tags=platform,
                        parent=event,
                    )
                    await self.emit_event(
                        repo_event,
                        context=f"{{module}} detected {platform} {{event.type}} at {url}",
                    )
