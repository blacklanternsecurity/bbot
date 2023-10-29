from baddns.base import get_all_modules
from .base import BaseModule


class baddns(BaseModule):
    watched_events = ["DNS_NAME", "DNS_NAME_UNRESOLVED"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "safe", "web-basic"]
    meta = {"description": "Check subdomains for for subdomain takeovers and other DNS tomfoolery"}
    max_event_handlers = 8
    deps_pip = ["baddns"]

    async def handle_event(self, event):
        all_modules = get_all_modules()
        for ModuleClass in all_modules:
            module_instance = ModuleClass(
                event.data,
                http_client_class=self.scan.helpers.web.AsyncClient,
                dns_client=self.scan.helpers.dns.resolver,
            )
            if await module_instance.dispatch():
                results = module_instance.analyze()
                if results and len(results) > 0:
                    for r in results:
                        r_dict = r.to_dict()

                        if r_dict["confidence"] in ["CONFIRMED", "PROBABLE"]:
                            data = {
                                "severity": "MEDIUM",
                                "description": f"{r_dict['description']} Confidence: [{r_dict['confidence']}] Signature: [{r_dict['signature']}] Indicator: [{r_dict['indicator']}] Trigger: [{r_dict['trigger']}] baddns Module: [{r_dict['module']}]",
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
