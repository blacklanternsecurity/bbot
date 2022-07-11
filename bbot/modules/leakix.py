from .crobat import crobat


class leakix(crobat):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive"]

    base_url = "https://leakix.net"

    def query(self, query):
        headers = {"Accept": "application/json"}
        r = self.helpers.request(f"{self.base_url}/domain/{self.helpers.quote(query)}", headers=headers)
        if not r:
            return
        try:
            j = r.json()
        except Exception:
            self.warning(f"Error decoding JSON")
            return
        return set(self.parse_json(j))

    @staticmethod
    def clean_dns_name(dns_name):
        return str(dns_name).strip().lower().lstrip(".*")

    def parse_json(self, j):
        for key in ["host", "domain", "cn"]:
            for v in self.helpers.search_dict_by_key(key, j):
                if type(v) == list and all(type(x) == str for x in v):
                    for s in v:
                        s = self.clean_dns_name(s)
                        if s:
                            yield s
                elif type(v) == str:
                    v = self.clean_dns_name(v)
                    if v:
                        yield v
