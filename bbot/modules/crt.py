from bbot.modules.templates.subdomain_enum import subdomain_enum


class crt(subdomain_enum):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "description": "Query crt.sh (certificate transparency) for subdomains",
        "created_date": "2022-05-13",
        "author": "@TheTechromancer",
    }

    base_url = "https://crt.sh"
    reject_wildcards = False

    async def setup(self):
        self.cert_ids = set()
        return await super().setup()

    async def request_url(self, query):
        params = {"q": f"%.{query}", "output": "json"}
        url = self.helpers.add_get_params(self.base_url, params).geturl()
        return await self.request_with_fail_count(url, timeout=self.http_timeout + 30)

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
                            yield d.lower()
