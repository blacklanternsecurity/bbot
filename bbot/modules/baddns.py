from baddns.base import get_all_modules
from baddns.lib.loader import load_signatures
from .base import BaseModule

import asyncio
import logging


class baddns(BaseModule):
    watched_events = ["DNS_NAME", "DNS_NAME_UNRESOLVED"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "safe", "web-basic", "baddns", "cloud-enum", "subdomain-hijack"]
    meta = {
        "description": "Check hosts for domain/subdomain takeovers",
        "created_date": "2024-01-18",
        "author": "@liquidsec",
    }
    options = {"custom_nameservers": [], "only_high_confidence": False, "enable_references": False}
    options_desc = {
        "custom_nameservers": "Force BadDNS to use a list of custom nameservers",
        "only_high_confidence": "Do not emit low-confidence or generic detections",
        "enable_references": "Enable the references module (off by default)",
    }
    module_threads = 8
    deps_pip = ["baddns~=1.1.798"]

    def select_modules(self):

        module_list = ["CNAME", "NS", "MX", "TXT"]
        if self.config.get("enable_references", False):
            module_list.append("references")

        selected_modules = []
        for m in get_all_modules():
            if m.name in module_list:
                selected_modules.append(m)
        return selected_modules

    async def setup(self):
        self.preset.core.logger.include_logger(logging.getLogger("baddns"))
        self.custom_nameservers = self.config.get("custom_nameservers", []) or None
        if self.custom_nameservers:
            self.custom_nameservers = self.helpers.chain_lists(self.custom_nameservers)
        self.only_high_confidence = self.config.get("only_high_confidence", False)
        self.signatures = load_signatures()
        return True

    async def handle_event(self, event):

        tasks = []
        for ModuleClass in self.select_modules():
            module_instance = ModuleClass(
                event.data,
                http_client_class=self.scan.helpers.web.AsyncClient,
                dns_client=self.scan.helpers.dns.resolver,
                custom_nameservers=self.custom_nameservers,
                signatures=self.signatures,
            )
            tasks.append((module_instance, asyncio.create_task(module_instance.dispatch())))

        for module_instance, task in tasks:
            if await task:
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
                            await self.emit_event(
                                data,
                                "VULNERABILITY",
                                event,
                                tags=[f"baddns-{module_instance.name.lower()}"],
                                context=f'{{module}}\'s "{r_dict["module"]}" module found {{event.type}}: {r_dict["description"]}',
                            )

                        elif r_dict["confidence"] in ["UNLIKELY", "POSSIBLE"] and not self.only_high_confidence:
                            data = {
                                "description": f"{r_dict['description']} Confidence: [{r_dict['confidence']}] Signature: [{r_dict['signature']}] Indicator: [{r_dict['indicator']}] Trigger: [{r_dict['trigger']}] baddns Module: [{r_dict['module']}]",
                                "host": str(event.host),
                            }
                            await self.emit_event(
                                data,
                                "FINDING",
                                event,
                                tags=[f"baddns-{module_instance.name.lower()}"],
                                context=f'{{module}}\'s "{r_dict["module"]}" module found {{event.type}}: {r_dict["description"]}',
                            )
                        else:
                            self.warning(f"Got unrecognized confidence level: {r['confidence']}")

                        found_domains = r_dict.get("found_domains", None)
                        if found_domains:
                            for found_domain in found_domains:
                                await self.emit_event(
                                    found_domain,
                                    "DNS_NAME",
                                    event,
                                    tags=[f"baddns-{module_instance.name.lower()}"],
                                    context=f'{{module}}\'s "{r_dict["module"]}" module found {{event.type}}: {{event.data}}',
                                )
