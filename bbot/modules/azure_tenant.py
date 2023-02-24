import re

from .viewdns import viewdns


class azure_tenant(viewdns):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["affiliates", "subdomain-enum", "passive", "safe"]
    meta = {"description": "Query Azure for tenant sister domains"}

    base_url = "https://autodiscover-s.outlook.com"
    in_scope_only = True

    def setup(self):
        self.processed = set()
        self.d_xml_regex = re.compile(r"<Domain>([^<>/]*)</Domain>", re.I)
        return True

    def handle_event(self, event):
        _, query = self.helpers.split_domain(event.data)
        domains, _ = self.query(query)
        if domains:
            self.success(f'Found {len(domains):,} domains under tenant for "{query}"')
        for domain in domains:
            if domain != query:
                self.emit_event(domain, "DNS_NAME", source=event, tags=["affiliate"])
        # todo: tenants?

    def query(self, domain):
        url = f"{self.base_url}/autodiscover/autodiscover.svc"
        data = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <soap:Header>
        <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
        <a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
    </soap:Header>
    <soap:Body>
        <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
            <Request>
                <Domain>{domain}</Domain>
            </Request>
        </GetFederationInformationRequestMessage>
    </soap:Body>
</soap:Envelope>"""

        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": '"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"',
            "User-Agent": "AutodiscoverClient",
            "Accept-Encoding": "identity",
        }

        self.debug(f"Retrieving tenant domains at {url}")

        r = self.request_with_fail_count(url, method="POST", headers=headers, data=data)
        status_code = getattr(r, "status_code", 0)
        if status_code not in (200, 421):
            self.warning(f'Error retrieving azure_tenant domains for "{domain}" (status code: {status_code})')
            return set(), set()
        found_domains = list(set(self.d_xml_regex.findall(r.text)))
        domains = set()
        tenantnames = set()

        for d in found_domains:
            # tenant names
            if d.lower().endswith(".onmicrosoft.com"):
                tenantnames.add(d.split(".")[0].lower())
            # make sure we don't make any unnecessary api calls
            d = str(d).lower()
            _, query = self.helpers.split_domain(d)
            self.processed.add(hash(query))
            domains.add(d)
            # absorb into word cloud
            self.scan.word_cloud.absorb_word(d)

        return domains, tenantnames
