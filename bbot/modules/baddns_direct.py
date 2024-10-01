from baddns.base import get_all_modules
from baddns.lib.loader import load_signatures
from .base import BaseModule

import logging


class baddns_direct(BaseModule):
    watched_events = ["URL", "STORAGE_BUCKET"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "safe", "subdomain-enum", "baddns", "cloud-enum"]
    meta = {
        "description": "Check for unusual subdomain / service takeover edge cases that require direct detection",
        "created_date": "2024-01-29",
        "author": "@liquidsec",
    }
    options = {"custom_nameservers": []}
    options_desc = {
        "custom_nameservers": "Force BadDNS to use a list of custom nameservers",
    }
    module_threads = 8
    deps_pip = ["baddns~=1.1.864"]

    scope_distance_modifier = 1

    async def setup(self):
        self.preset.core.logger.include_logger(logging.getLogger("baddns"))
        self.custom_nameservers = self.config.get("custom_nameservers", []) or None
        if self.custom_nameservers:
            self.custom_nameservers = self.helpers.chain_lists(self.custom_nameservers)
        self.only_high_confidence = self.config.get("only_high_confidence", False)
        self.signatures = load_signatures()
        return True

    def select_modules(self):
        selected_modules = []
        for m in get_all_modules():
            if m.name in ["CNAME"]:
                selected_modules.append(m)
        return selected_modules

    async def handle_event(self, event):
        CNAME_direct_module = self.select_modules()[0]
        kwargs = {
            "http_client_class": self.scan.helpers.web.AsyncClient,
            "dns_client": self.scan.helpers.dns.resolver,
            "custom_nameservers": self.custom_nameservers,
            "signatures": self.signatures,
            "direct_mode": True,
        }

        CNAME_direct_instance = CNAME_direct_module(event.host, **kwargs)
        if await CNAME_direct_instance.dispatch():

            results = CNAME_direct_instance.analyze()
            if results and len(results) > 0:
                for r in results:
                    r_dict = r.to_dict()

                    data = {
                        "description": f"Possible [{r_dict['signature']}] via direct BadDNS analysis. Indicator: [{r_dict['indicator']}] Trigger: [{r_dict['trigger']}] baddns Module: [{r_dict['module']}]",
                        "host": str(event.host),
                    }

                    await self.emit_event(
                        data,
                        "FINDING",
                        event,
                        tags=[f"baddns-{CNAME_direct_module.name.lower()}"],
                        context=f'{{module}}\'s "{r_dict["module"]}" module found {{event.type}}: {r_dict["description"]}',
                    )
        await CNAME_direct_instance.cleanup()

    async def filter_event(self, event):
        if event.type == "STORAGE_BUCKET":
            if str(event.module).startswith("bucket_"):
                return False
            self.debug(f"Processing STORAGE_BUCKET for {event.host}")
        if event.type == "URL":
            if event.scope_distance > 0:
                self.debug(
                    f"Rejecting {event.host} due to not being in scope (scope distance: {str(event.scope_distance)})"
                )
                return False
            if "cdn-cloudflare" not in event.tags:
                self.debug(f"Rejecting {event.host} due to not being behind CloudFlare")
                return False
            if "status-200" in event.tags or "status-301" in event.tags:
                self.debug(f"Rejecting {event.host} due to lack of non-standard status code")
                return False

            self.debug(f"Passed all checks and is processing {event.host}")
        return True
