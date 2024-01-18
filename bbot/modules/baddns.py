from baddns.base import get_all_modules
from .base import BaseModule

import logging
from bbot.core.logger.logger import include_logger

include_logger(logging.getLogger("baddns"))


class baddns(BaseModule):
    watched_events = ["DNS_NAME", "DNS_NAME_UNRESOLVED"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "safe", "web-basic"]
    meta = {"description": "Check subdomains for for subdomain takeovers and other DNS tomfoolery"}
    options = {"custom_nameservers": []}
    options_desc = {
        "custom_nameservers": "Force BadDNS to use a list of custom nameservers",
    }
    max_event_handlers = 8
    deps_pip = ["baddns"]

    async def setup(self):
        self.custom_nameservers = self.config.get("custom_nameservers", []) or None
        if self.custom_nameservers:
            self.custom_nameservers = self.helpers.chain_lists(self.custom_nameservers)
        return True

    async def handle_event(self, event):
        all_modules = get_all_modules()
        for ModuleClass in all_modules:
            module_instance = ModuleClass(
                event.data,
                http_client_class=self.scan.helpers.web.AsyncClient,
                dns_client=self.scan.helpers.dns.resolver,
                custom_nameservers=self.custom_nameservers,
            )
            if await module_instance.dispatch():
                results = module_instance.analyze()
                if results and len(results) > 0:
                    for r in results:
                        r_dict = r.to_dict()

                        if r_dict["confidence"] in ["CONFIRMED", "PROBABLE"]:
                            data = {
                                "severity": "MEDIUM",
                                "description": f"{r_dict['description']}. Confidence: [{r_dict['confidence']}] Signature: [{r_dict['signature']}] Indicator: [{r_dict['indicator']}] Trigger: [{r_dict['trigger']}] baddns Module: [{r_dict['module']}]",
                                "host": str(event.host),
                            }
                            self.emit_event(data, "VULNERABILITY", event)

                        elif r_dict["confidence"] in ["UNLIKELY", "POSSIBLE"]:
                            data = {
                                "description": f"{r_dict['description']} Confidence: [{r_dict['confidence']}] Signature: [{r_dict['signature']}] Indicator: [{r_dict['indicator']}] Trigger: [{r_dict['trigger']}] baddns Module: [{r_dict['module']}]",
                                "host": str(event.host),
                            }
                            self.emit_event(data, "FINDING", event)
                        else:
                            log.warning(f"Got unrecognized confidence level: {r['confidence']}")

                        found_domains = r_dict.get("found_domains", None)
                        if found_domains:
                            for found_domain in found_domains:
                                self.emit_event(found_domain, "DNS_NAME", event)
