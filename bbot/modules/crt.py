from urllib.parse import urlencode

from .crobat import crobat


class crt(crobat):

    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]

    base_url = "https://crt.sh"

    def setup(self):
        self.cert_ids = set()
        return super().setup()

    def query(self, domain):
        params = {"q": domain, "output": "json"}
        url = f"{self.base_url}?{urlencode(params)}"
        res = self.helpers.request(url)
        j = {}
        try:
            j = res.json()
        except Exception:
            import traceback

            self.warning("Error decoding JSON")
            self.debug(traceback.format_exc())
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
