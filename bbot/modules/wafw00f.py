from bbot.modules.base import BaseModule
from wafw00f import main as wafw00f_main


class wafw00f(BaseModule):
    """
    https://github.com/EnableSecurity/wafw00f
    """

    watched_events = ["URL"]
    produced_events = ["WAF"]
    flags = ["active", "aggressive"]
    meta = {"description": "Web Application Firewall Fingerprinting Tool"}

    deps_pip = ["wafw00f~=2.2.0"]

    options = {"generic_detect": True}
    options_desc = {"generic_detect": "When no specific WAF detections are made, try to peform a generic detect"}

    in_scope_only = True
    per_host_only = True

    async def handle_event(self, event):
        host = f"{event.parsed.scheme}://{event.parsed.netloc}/"
        WW = await self.scan.run_in_executor(wafw00f_main.WAFW00F, host)
        waf_detections = await self.scan.run_in_executor(WW.identwaf)
        if waf_detections:
            for waf in waf_detections:
                self.emit_event({"host": host, "WAF": waf}, "WAF", source=event)
        else:
            if self.config.get("generic_detect") == True:
                generic = await self.scan.run_in_executor(WW.genericdetect)
                if generic:
                    self.emit_event(
                        {"host": host, "WAF": "generic detection", "info": WW.knowledge["generic"]["reason"]},
                        "WAF",
                        source=event,
                    )
