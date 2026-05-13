from bbot.modules.base import BaseInterceptModule
from bbot.core.config.models import BaseModuleConfig, Field


class portfilter(BaseInterceptModule):
    watched_events = ["OPEN_TCP_PORT", "URL_UNVERIFIED", "URL"]
    flags = ["safe", "passive"]
    meta = {
        "description": "Filter out unwanted open ports from cloud/CDN targets",
        "created_date": "2025-01-06",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        cdn_tags: str = Field("cdn,waf", description="Comma-separated list of tags to skip, e.g. 'cdn,waf'")
        allowed_cdn_ports: str = Field(
            "80,443", description="Comma-separated list of ports that are allowed to be scanned for CDNs"
        )

    _priority = 4
    # we consume URLs but we don't want to automatically enable blasthttp
    _disable_auto_module_deps = True

    async def setup(self):
        self.cdn_tags = [t.strip() for t in self.config.get("cdn_tags", "").split(",")]
        self.allowed_cdn_ports = self.config.get("allowed_cdn_ports", "").strip()
        if self.allowed_cdn_ports:
            try:
                self.allowed_cdn_ports = [int(p.strip()) for p in self.allowed_cdn_ports.split(",")]
            except Exception as e:
                return False, f"Error parsing allowed CDN ports '{self.allowed_cdn_ports}': {e}"
        return True

    async def handle_event(self, event, **kwargs):
        # if the port isn't in our list of allowed CDN ports
        if event.port not in self.allowed_cdn_ports:
            for cdn_tag in self.cdn_tags:
                if cdn_tag in event.tags:
                    return (
                        False,
                        f"event has tag '{cdn_tag}' and the port is not in the allowed list",
                    )
        return True
