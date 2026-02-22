from bbot.modules.templates.thc_lookup_base import thc_lookup_base


class thc_rdns(thc_lookup_base):
    watched_events = ["IP_ADDRESS"]
    produced_events = ["DNS_NAME"]
    flags = ["passive", "safe"]
    meta = {
        "description": "Query ip.thc.org reverse DNS by IP",
        "created_date": "2026-02-19",
        "author": "@carlospolop",
    }
    options = {"limit": 100, "max_pages": 3, "tld": "", "apex_domain": ""}
    options_desc = {
        "limit": "Maximum results per API page",
        "max_pages": "Maximum number of API pages to fetch per query",
        "tld": "Optional comma-separated list of TLD filters (e.g. com,net,org)",
        "apex_domain": "Optional apex domain filter (e.g. example.com)",
    }

    api_url = "https://ip.thc.org/lookup"
    legacy_url = "https://ip.thc.org"

    async def setup(self):
        self.limit = max(1, int(self.config.get("limit", 100)))
        self.max_pages = max(1, int(self.config.get("max_pages", 3)))
        self.apex_domain = str(self.config.get("apex_domain", "")).strip()
        tld_str = str(self.config.get("tld", "")).strip()
        self.tlds = [t.strip().lstrip(".") for t in tld_str.split(",") if t.strip()]
        return await super().setup()

    def _incoming_dedup_hash(self, event):
        return hash(event.data), "dedup_strategy=ip_address"

    async def handle_event(self, event):
        ip = str(event.data)
        results = await self.query(ip)
        for hostname in sorted(results):
            try:
                hostname = self.helpers.validators.validate_host(hostname)
            except ValueError as exc:
                self.verbose(exc)
                continue
            await self.emit_event(
                hostname,
                "DNS_NAME",
                event,
                context=f'{{module}} searched ip.thc.org reverse DNS for "{ip}" and found {{event.type}}: {{event.data}}',
            )

    async def query(self, ip_address):
        results = set()

        page_state = ""
        for _ in range(self.max_pages):
            body = {"ip_address": ip_address, "page_state": page_state, "limit": self.limit}
            if self.tlds:
                body["tld"] = self.tlds
            if self.apex_domain:
                body["apex_domain"] = self.apex_domain

            response = await self.helpers.request(self.api_url, method="POST", json=body)
            data = self._safe_json(response)
            domains = data.get("domains", [])
            if not isinstance(domains, list):
                break

            for entry in domains:
                if not isinstance(entry, dict):
                    continue
                domain = str(entry.get("domain", "")).strip().rstrip(".")
                if domain:
                    results.add(domain)

            page_state = str(data.get("next_page_state", "")).strip()
            if not page_state:
                return results

        if results:
            return results
        return await self._query_legacy(ip_address)

    async def _query_legacy(self, ip_address):
        results = set()
        next_url = f"{self.legacy_url}/{ip_address}?l={self.limit}"

        for _ in range(self.max_pages):
            response = await self.helpers.request(next_url)
            if response is None:
                break
            text = response.text or ""
            page_results, next_page = self._parse_legacy_page(text)
            results.update(page_results)
            if not next_page:
                break
            next_url = next_page
        return results
