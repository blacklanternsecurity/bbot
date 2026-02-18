from bbot.modules.base import BaseModule


class azure_tenant(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["affiliates", "subdomain-enum", "cloud-enum", "passive", "safe"]
    meta = {
        "description": "Query Azure via azmap.dev for tenant sister domains",
        "created_date": "2024-07-04",
        "author": "@TheTechromancer",
    }

    base_url = "https://azmap.dev/api/tenant"
    in_scope_only = True
    per_domain_only = True

    async def setup(self):
        self.processed = set()
        return True

    async def handle_event(self, event):
        _, query = self.helpers.split_domain(event.data)
        tenant_data = await self.query(query)

        if not tenant_data:
            return

        tenant_id = tenant_data.get("tenant_id")
        tenant_name = tenant_data.get("tenant_name")
        email_domains = tenant_data.get("email_domains", [])

        if email_domains:
            self.verbose(
                f'Found {len(email_domains):,} domains under tenant for "{query}": {", ".join(sorted(email_domains))}'
            )
            for domain in email_domains:
                if domain != query:
                    await self.emit_event(
                        domain,
                        "DNS_NAME",
                        parent=event,
                        tags=["affiliate", "azure-tenant"],
                        context=f'{{module}} queried azmap.dev for "{query}" and found {{event.type}}: {{event.data}}',
                    )

            # Build tenant names list (include the tenant name from the API)
            tenant_names = []
            if tenant_name:
                tenant_names.append(tenant_name)

            # Also extract tenant names from .onmicrosoft.com domains
            for domain in email_domains:
                if domain.lower().endswith(".onmicrosoft.com"):
                    tenantname = domain.split(".")[0].lower()
                    if tenantname and tenantname not in tenant_names:
                        tenant_names.append(tenantname)

            event_data = {"tenant-names": tenant_names, "domains": sorted(email_domains)}
            tenant_names_str = ",".join(tenant_names)
            if tenant_id:
                event_data["tenant-id"] = tenant_id
            await self.emit_event(
                event_data,
                "AZURE_TENANT",
                parent=event,
                context=f'{{module}} queried azmap.dev for "{query}" and found {{event.type}}: {tenant_names_str}',
            )

    async def query(self, domain):
        url = f"{self.base_url}?domain={domain}&extract=true"

        self.debug(f"Retrieving tenant domains at {url}")

        r = await self.helpers.request(url)
        status_code = getattr(r, "status_code", 0)
        if status_code != 200:
            self.verbose(f'Error retrieving azure_tenant domains for "{domain}" (status code: {status_code})')
            return {}

        try:
            tenant_data = r.json()
        except Exception as e:
            self.warning(f'Error parsing JSON response for "{domain}": {e}')
            return {}

        # Absorb domains into word cloud
        email_domains = tenant_data.get("email_domains", [])
        for d in email_domains:
            d = str(d).lower()
            _, query = self.helpers.split_domain(d)
            self.processed.add(hash(query))
            self.scan.word_cloud.absorb_word(d)

        return tenant_data
