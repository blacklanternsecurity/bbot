import re

from bbot.modules.base import BaseModule


class root_domains(BaseModule):
    """
    Used as a base for modules that only act on root domains and not individual hostnames
    """

    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["passive", "safe"]
    meta = {
        "description": "",
    }
    in_scope_only = True
    _qsize = 1

    async def setup(self):
        self.processed = set()
        self.date_regex = re.compile(r"\d{4}-\d{2}-\d{2}")
        return True

    async def filter_event(self, event):
        _, domain = self.helpers.split_domain(event.data)
        if hash(domain) in self.processed:
            return False
        self.processed.add(hash(domain))
        return True
