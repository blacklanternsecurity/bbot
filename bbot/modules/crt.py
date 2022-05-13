from urllib.parse import urlencode

from .base import BaseModule


class crt(BaseModule):

    flags = ["subdomain-enum"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]

    def setup(self):
        self.processed = set()
        self.cert_ids = set()
        return True

    def filter_event(self, event):
        if "target" in event.tags:
            return True
        elif hash(self.helpers.parent_domain(event.data)) not in self.processed:
            return True
        return False

    def handle_event(self, event):
        if not "target" in event.tags:
            query = self.helpers.parent_domain(event.data).lower()
        else:
            query = str(event.data).lower()

        if hash(query) not in self.processed:
            self.processed.add(hash(query))
            for hostname in self.query(query):
                if not hostname == event:
                    self.emit_event(hostname, "DNS_NAME", event)
                else:
                    self.debug(f"Invalid DNS name: {hostname}")

    def query(self, domain):
        params = {"q": domain, "output": "json"}
        base_url = "https://crt.sh?"
        url = f"{base_url}{urlencode(params)}"
        res = self.helpers.request(url)
        j = res.json()
        for cert_info in j:
            if not type(cert_info) == dict:
                continue
            cert_id = cert_info.get("id")
            if cert_id:
                if hash(cert_id) not in self.cert_ids:
                    self.cert_ids.add(hash(cert_id))
                    domain = cert_info.get("name_value")
                    if domain:
                        for d in domain.splitlines():
                            yield d.lower().strip("*.")
