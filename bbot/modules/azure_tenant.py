import regex as re
from contextlib import suppress

from bbot.modules.base import BaseModule


class azure_tenant(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["affiliates", "subdomain-enum", "cloud-enum", "passive", "safe"]
    meta = {
        "description": "Query Azure for tenant sister domains",
        "created_date": "2024-07-04",
        "author": "@TheTechromancer",
    }

    base_url = "https://autodiscover-s.outlook.com"
    in_scope_only = True
    per_domain_only = True

    async def setup(self):
        self.processed = set()
        self.d_xml_regex = re.compile(r"<Domain>([^<>/]*)</Domain>", re.I)
        return True

    async def handle_event(self, event):
        _, query = self.helpers.split_domain(event.data)
        domains, openid_config = await self.query(query)

        tenant_id = None
        authorization_endpoint = openid_config.get("authorization_endpoint", "")
        matches = await self.helpers.re.findall(self.helpers.regexes.uuid_regex, authorization_endpoint)
        if matches:
            tenant_id = matches[0]

        tenant_names = set()
        if domains:
            self.verbose(f'Found {len(domains):,} domains under tenant for "{query}": {", ".join(sorted(domains))}')
            for domain in domains:
                if domain != query:
                    await self.emit_event(
                        domain,
                        "DNS_NAME",
                        parent=event,
                        tags=["affiliate", "azure-tenant"],
                        context=f'{{module}} queried Outlook autodiscover for "{query}" and found {{event.type}}: {{event.data}}',
                    )
                    # tenant names
                    if domain.lower().endswith(".onmicrosoft.com"):
                        tenantname = domain.split(".")[0].lower()
                        if tenantname:
                            tenant_names.add(tenantname)

            tenant_names = sorted(tenant_names)
            event_data = {"tenant-names": tenant_names, "domains": sorted(domains)}
            tenant_names_str = ",".join(tenant_names)
            if tenant_id is not None:
                event_data["tenant-id"] = tenant_id
            await self.emit_event(
                event_data,
                "AZURE_TENANT",
                parent=event,
                context=f'{{module}} queried Outlook autodiscover for "{query}" and found {{event.type}}: {tenant_names_str}',
            )

    async def query(self, domain):
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

        autodiscover_task = self.helpers.create_task(
            self.helpers.request(url, method="POST", headers=headers, content=data)
        )
        openid_url = f"https://login.windows.net/{domain}/.well-known/openid-configuration"
        openid_task = self.helpers.create_task(self.helpers.request(openid_url))

        r = await autodiscover_task
        status_code = getattr(r, "status_code", 0)
        if status_code not in (200, 421):
            self.verbose(f'Error retrieving azure_tenant domains for "{domain}" (status code: {status_code})')
            return set(), dict()
        found_domains = list(set(await self.helpers.re.findall(self.d_xml_regex, r.text)))
        domains = set()

        for d in found_domains:
            # make sure we don't make any unnecessary api calls
            d = str(d).lower()
            _, query = self.helpers.split_domain(d)
            self.processed.add(hash(query))
            domains.add(d)
            # absorb into word cloud
            self.scan.word_cloud.absorb_word(d)

        r = await openid_task
        openid_config = dict()
        with suppress(Exception):
            openid_config = r.json()

        domains = sorted(domains)
        return domains, openid_config
