from bbot.modules.base import BaseModule
from wafw00f import main as wafw00f_main

# disable wafw00f logging
import logging

wafw00f_logger = logging.getLogger("wafw00f")
wafw00f_logger.setLevel(logging.CRITICAL + 100)


class wafw00f(BaseModule):
    """
    https://github.com/EnableSecurity/wafw00f
    """

    watched_events = ["URL"]
    produced_events = ["WAF"]
    flags = ["active", "aggressive"]
    meta = {
        "description": "Web Application Firewall Fingerprinting Tool",
        "created_date": "2023-02-15",
        "author": "@liquidsec",
    }

    deps_pip = ["wafw00f~=2.2.0"]

    options = {"generic_detect": True}
    options_desc = {"generic_detect": "When no specific WAF detections are made, try to perform a generic detect"}

    in_scope_only = True
    per_hostport_only = True

    async def filter_event(self, event):
        http_status = getattr(event, "http_status", 0)
        if not http_status or str(http_status).startswith("3"):
            return False, f"Invalid HTTP status code: {http_status}"
        return True, ""

    def _incoming_dedup_hash(self, event):
        return hash(f"{event.parsed_url.scheme}://{event.parsed_url.netloc}/")

    async def handle_event(self, event):
        url = f"{event.parsed_url.scheme}://{event.parsed_url.netloc}/"
        WW = await self.helpers.run_in_executor(wafw00f_main.WAFW00F, url, followredirect=False)
        waf_detections = await self.helpers.run_in_executor(WW.identwaf)
        if waf_detections:
            for waf in waf_detections:
                await self.emit_event(
                    {"host": str(event.host), "url": url, "waf": waf},
                    "WAF",
                    parent=event,
                    context=f"{{module}} scanned {url} and identified {{event.type}}: {waf}",
                )
        else:
            if self.config.get("generic_detect") == True:
                generic = await self.helpers.run_in_executor(WW.genericdetect)
                if generic:
                    waf = "generic detection"
                    await self.emit_event(
                        {
                            "host": str(event.host),
                            "url": url,
                            "waf": waf,
                            "info": WW.knowledge["generic"]["reason"],
                        },
                        "WAF",
                        parent=event,
                        context=f"{{module}} scanned {url} and identified {{event.type}}: {waf}",
                    )
