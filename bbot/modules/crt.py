from urllib.parse import urlencode

from .crobat import crobat


class crt(crobat):

    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {"description": "Query crt.sh (certificate transparency) for subdomains"}

    base_url = "https://crt.sh"

    def setup(self):
        self.cert_ids = set()
        return super().setup()

    def request_url(self, query):
        params = {"q": query, "output": "json"}
        return self.helpers.request(f"{self.base_url}?{urlencode(params)}")

    def parse_results(self, r, query):
        j = r.json()
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
