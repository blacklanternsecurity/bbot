from contextlib import suppress

from censys.common import exceptions
from censys.search import CensysHosts
from censys.search import CensysCertificates

from bbot.modules.shodan_dns import shodan_dns


class censys(shodan_dns):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME", "EMAIL_ADDRESS", "IP_ADDRESS", "OPEN_PORT", "PROTOCOL"]
    flags = ["subdomain-enum", "email-enum", "passive", "safe"]
    meta = {"description": "Query the Censys API", "auth_required": True}
    options = {"api_id": "", "api_secret": "", "max_records": 1000}
    options_desc = {
        "api_id": "Censys.io API ID",
        "api_secret": "Censys.io API Secret",
        "max_records": "Limit results to help prevent exceeding API quota",
    }

    deps_pip = ["censys"]

    def setup(self):
        self.max_records = self.config.get("max_records", 1000)
        self.api_id = self.config.get("api_id", "")
        self.api_secret = self.config.get("api_secret", "")
        self._cert_name_threshold = 20
        with suppress(Exception):
            self.hosts = CensysHosts(api_id=self.api_id, api_secret=self.api_secret)
        with suppress(Exception):
            self.certificates = CensysCertificates(api_id=self.api_id, api_secret=self.api_secret)
        return super().setup()

    def ping(self):
        quota = self.certificates.quota()
        used = int(quota["used"])
        allowance = int(quota["allowance"])
        assert used < allowance, "No quota remaining"

    def query(self, query):
        emails = set()
        dns_names = set()
        ip_addresses = dict()
        try:
            # certificates
            certificate_query = f"parsed.names: {query}"
            certificate_fields = ["parsed.names", "parsed.issuer_dn", "parsed.subject_dn"]
            for result in self.certificates.search(
                certificate_query, fields=certificate_fields, max_records=self.max_records
            ):
                parsed_names = result.get("parsed.names", [])
                # helps filter out third-party certs with a lot of garbage names
                _filter = lambda x: True
                domain = self.helpers.tldextract(query).domain
                if len(parsed_names) > self._cert_name_threshold:
                    _filter = lambda x: domain in str(x.lower())
                parsed_names = list(filter(_filter, parsed_names))
                dns_names.update(set([n.lstrip(".*").rstrip(".").lower() for n in parsed_names]))
                emails.update(set(self.helpers.extract_emails(result.get("parsed.issuer_dn", ""))))
                emails.update(set(self.helpers.extract_emails(result.get("parsed.subject_dn", ""))))

            # hosts
            per_page = 100
            pages = max(1, int(self.max_records / per_page))
            hosts_query = f"services.tls.certificates.leaf_data.names: {query} or services.tls.certificates.leaf_data.subject.email_address: {query}"
            for i, page in enumerate(self.hosts.search(hosts_query, per_page=per_page, pages=pages)):
                for result in page:
                    ip = result.get("ip", "")
                    if not ip:
                        continue
                    ip_addresses[ip] = []
                    services = result.get("services", [])
                    for service in services:
                        port = service.get("port")
                        service_name = service.get("service_name", "")
                        transport_protocol = service.get("transport_protocol", "")
                        if not port or not transport_protocol:
                            continue
                        ip_addresses[ip].append((port, service_name, transport_protocol))
                if self.scan.stopping:
                    break

        except exceptions.CensysRateLimitExceededException:
            self.warning("Exceeded Censys account limits")
        except exceptions.CensysException as e:
            self.warning(f"Error with API: {e}")
        except Exception as e:
            self.warning(f"Unknown error: {e}")

        return emails, dns_names, ip_addresses

    def handle_event(self, event):
        query = self.make_query(event)
        emails, dns_names, ip_addresses = self.query(query)
        for email in emails:
            self.emit_event(email, "EMAIL_ADDRESS", source=event)
        for dns_name in dns_names:
            self.emit_event(dns_name, "DNS_NAME", source=event)
        for ip, services in ip_addresses.items():
            ip_event = self.make_event(ip, "IP_ADDRESS", source=event)
            if not ip_event:
                continue
            self.emit_event(ip_event)
            for port, service_name, transport_protocol in services:
                port_data = self.helpers.make_netloc(ip, port)
                port_type = f"OPEN_{transport_protocol.upper()}_PORT"
                port_event = self.make_event(port_data, port_type, source=ip_event)
                if not port_event:
                    continue
                self.emit_event(port_event)
                if service_name:
                    service_name = str(service_name).upper()
                    protocol_data = {"host": port_data, "protocol": service_name}
                    self.emit_event(protocol_data, "PROTOCOL", source=port_event)

    @property
    def auth_secret(self):
        return self.api_id and self.api_secret
