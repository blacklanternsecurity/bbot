from bbot.modules.base import BaseModule


class credential_leak(BaseModule):
    """
    A typical free API-based subdomain enumeration module
    Inherited by many other modules including sublist3r, dnsdumpster, etc.
    """

    async def setup(self):
        self.queries_processed = set()
        self.data_seen = set()
        return True

    async def filter_event(self, event):
        query = self.make_query(event)
        query_hash = hash(query)
        if query_hash not in self.queries_processed:
            self.queries_processed.add(query_hash)
            return True
        return False, f'Already processed "{query}"'

    def make_query(self, event):
        if "target" in event.tags:
            return event.data
        _, domain = self.helpers.split_domain(event.data)
        return domain

    def already_seen(self, item):
        h = hash(item)
        already_seen = h in self.data_seen
        self.data_seen.add(h)
        return already_seen
