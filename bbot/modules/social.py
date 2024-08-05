import re
from bbot.modules.base import BaseModule


class social(BaseModule):
    watched_events = ["URL_UNVERIFIED"]
    produced_events = ["SOCIAL"]
    meta = {
        "description": "Look for social media links in webpages",
        "created_date": "2023-03-28",
        "author": "@TheTechromancer",
    }
    flags = ["passive", "safe", "social-enum"]

    # platform name : (regex, case_sensitive)
    social_media_platforms = {
        "linkedin": (r"linkedin.com/(?:in|company)/([a-zA-Z0-9-]+)", False),
        "facebook": (r"facebook.com/([a-zA-Z0-9.]+)", False),
        "twitter": (r"twitter.com/([a-zA-Z0-9_]{1,15})", False),
        "github": (r"github.com/([a-zA-Z0-9_-]+)", False),
        "instagram": (r"instagram.com/([a-zA-Z0-9_.]+)", False),
        "youtube": (r"youtube.com/@([a-zA-Z0-9_]+)", False),
        "bitbucket": (r"bitbucket.org/([a-zA-Z0-9_-]+)", False),
        "gitlab": (r"gitlab.(?:com|org)/([a-zA-Z0-9_-]+)", False),
        "discord": (r"discord.gg/([a-zA-Z0-9_-]+)", True),
        "docker": (r"hub.docker.com/[ru]/([a-zA-Z0-9_-]+)", False),
        "huggingface": (r"huggingface.co/([a-zA-Z0-9_-]+)", False),
    }

    scope_distance_modifier = 1

    async def setup(self):
        self.compiled_regexes = {k: (re.compile(v), c) for k, (v, c) in self.social_media_platforms.items()}
        return True

    async def handle_event(self, event):
        for platform, (regex, case_sensitive) in self.compiled_regexes.items():
            for match in regex.finditer(event.data):
                url = match.group()
                profile_name = match.groups()[0]
                if not case_sensitive:
                    url = url.lower()
                    profile_name = profile_name.lower()
                url = f"https://{url}"
                event_data = {"platform": platform, "url": url, "profile_name": profile_name}
                # only emit if the same event isn't already in the parent chain
                if not any([e.type == "SOCIAL" and e.data == event_data for e in event.get_parents()]):
                    social_event = self.make_event(
                        event_data,
                        "SOCIAL",
                        parent=event,
                    )
                    await self.emit_event(
                        social_event,
                        context=f"{{module}} detected {platform} {{event.type}} at {url}",
                    )
