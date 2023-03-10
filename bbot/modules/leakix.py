from .crobat import crobat


class leakix(crobat):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {"description": "Query leakix.net for subdomains"}

    base_url = "https://leakix.net"

    def handle_event(self, event):
        query = self.make_query(event)
        headers = {"Accept": "application/json"}
        r = self.request_with_fail_count(f"{self.base_url}/domain/{self.helpers.quote(query)}", headers=headers)
        if not r:
            return
        try:
            j = r.json()
        except Exception:
            self.verbose(f"Error decoding JSON")
            return
        services = j.get("Services", [])
        if services:
            for s in services:
                if s.get("event_type", "") != "service":
                    continue
                host = s.get("host", "")
                if not host:
                    continue
                if host == event:
                    source_event = event
                else:
                    source_event = self.make_event(host, "DNS_NAME", source=event)
                    if not source_event:
                        continue
                    self.emit_event(source_event)
                ssl = s.get("ssl", {})
                if not ssl:
                    continue
                certificate = ssl.get("certificate", {})
                if not certificate:
                    continue
                cert_domains = set()
                cn = self.clean_dns_name(certificate.get("cn", ""))
                if cn:
                    cert_domains.add(cn)
                domains = certificate.get("domain", [])
                if domains:
                    for d in domains:
                        d = self.clean_dns_name(d)
                        if d:
                            cert_domains.add(d)
                for d in cert_domains:
                    if d != host:
                        self.emit_event(d, "DNS_NAME", source=source_event)

    @staticmethod
    def clean_dns_name(dns_name):
        return str(dns_name).strip().lower().lstrip(".*")
