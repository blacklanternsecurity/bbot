from baddns.base import get_all_modules
from baddns.lib.loader import load_signatures
from urllib.parse import urlparse
from .base import BaseModule

import asyncio
import logging

class baddns_direct(BaseModule):
    watched_events = ["STORAGE_BUCKET"]
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
    deps_pip = ["baddns~=1.1.815"]

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

        self.critical("HANDLE EVENT")
        parsed_url = urlparse(event.data["url"])
        domain = parsed_url.netloc

        self.critical(domain)

        

        CNAME_direct_module =  self.select_modules()[0]
        kwargs = {
            "http_client_class": self.scan.helpers.web.AsyncClient,
            "dns_client": self.scan.helpers.dns.resolver,
            "custom_nameservers": self.custom_nameservers,
            "signatures": self.signatures,
        }

        CNAME_direct_instance = CNAME_direct_module(domain, **kwargs)
        await CNAME_direct_instance.dispatch()
        print(CNAME_direct_instance)
        results = CNAME_direct_instance.analyze()
        self.hugewarning(results)
        if results and len(results) > 0:
            for r in results:
                r_dict = r.to_dict()
                self.critical(r_dict)

    async def filter_event(self, event):
        if event.type == "STORAGE_BUCKET" and str(event.module).startswith("bucket_"):
            self.critical("KILLED BUCKET")
            return False
        return True
