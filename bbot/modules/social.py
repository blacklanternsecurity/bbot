import re
from bbot.modules.base import BaseModule


class social(BaseModule):
    watched_events = ["URL_UNVERIFIED"]
    produced_events = ["SOCIAL"]
    meta = {"description": "Look for social media links in webpages"}
    flags = ["active", "safe", "social-enum"]

    social_media_regex = {
        "linkedin": r"(?:https?:\/\/)?(?:www\.)?linkedin\.com\/(?:in|company)\/[a-zA-Z0-9-]+\/?",
        "facebook": r"(?:https?:\/\/)?(?:www\.)?facebook\.com\/[a-zA-Z0-9\.]+\/?",
        "twitter": r"(?:https?:\/\/)?(?:www\.)?twitter\.com\/[a-zA-Z0-9_]{1,15}\/?",
        "github": r"(?:https?:\/\/)?(?:www\.)?github\.com\/[a-zA-Z0-9_-]+\/?",
        "instagram": r"(?:https?:\/\/)?(?:www\.)?instagram\.com\/[a-zA-Z0-9_\.]+\/?",
        "youtube": r"(?:https?:\/\/)?(?:www\.)?youtube\.com\/[a-zA-Z0-9_]+\/?",
        "bitbucket": r"(?:https?:\/\/)?(?:www\.)?bitbucket\.org\/[a-zA-Z0-9_-]+\/?",
        "gitlab": r"(?:https?:\/\/)?(?:www\.)?gitlab\.com\/[a-zA-Z0-9_-]+\/?",
        "discord": r"(?:https?:\/\/)?(?:www\.)?discord\.gg\/[a-zA-Z0-9_-]+\/?",
    }

    scope_distance_modifier = 1

    async def setup(self):
        self.compiled_regexes = {k: re.compile(v) for k, v in self.social_media_regex.items()}
        return True

    async def handle_event(self, event):
        for platform, regex in self.compiled_regexes.items():
            for match in regex.findall(event.data):
                social_media_links = {"platform": platform, "url": match}
                self.emit_event(social_media_links, "SOCIAL", source=event)
