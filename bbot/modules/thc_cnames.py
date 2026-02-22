from bbot.modules.templates.thc_lookup_base import thc_lookup_base


class thc_cnames(thc_lookup_base):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["passive", "safe"]
    meta = {
        "description": "Query ip.thc.org for domains CNAME'd to a target domain",
        "created_date": "2026-02-19",
        "author": "@carlospolop",
    }
    options = {"limit": 100, "max_pages": 3}
    options_desc = {
        "limit": "Maximum results per API page",
        "max_pages": "Maximum number of API pages to fetch per query",
    }

    api_url = "https://ip.thc.org/lookup/cnames"
    legacy_url = "https://ip.thc.org/cn"

    async def setup(self):
        self.limit = max(1, int(self.config.get("limit", 100)))
        self.max_pages = max(1, int(self.config.get("max_pages", 3)))
        return await super().setup()

    def _incoming_dedup_hash(self, event):
        return hash(self.make_query(event)), "dedup_strategy=highest_parent"

    def make_query(self, event):
        query = event.data
        parents = list(reversed(list(self.helpers.domain_parents(event.data))))
        for parent in parents:
            if self.scan.in_scope(parent):
                query = parent
                break
        return ".".join([segment for segment in query.split(".") if segment != "_wildcard"])

    async def handle_event(self, event):
        query = self.make_query(event)
        results = await self.query(query)

        for domain in sorted(results):
            if domain == event.data:
                continue
            try:
                domain = self.helpers.validators.validate_host(domain)
            except ValueError as exc:
                self.verbose(exc)
                continue
            await self.emit_event(
                domain,
                "DNS_NAME",
                event,
                context=f'{{module}} searched ip.thc.org CNAMEs for "{query}" and found {{event.type}}: {{event.data}}',
            )

    async def query(self, query):
        results = set()

        page_state = ""
        for _ in range(self.max_pages):
            body = {"target_domain": query, "page_state": page_state, "limit": self.limit}
            response = await self.helpers.request(self.api_url, method="POST", json=body)
            data = self._safe_json(response)
            domains = data.get("domains", [])
            if not isinstance(domains, list):
                break
            for domain in domains:
                normalized = str(domain).strip().rstrip(".")
                if normalized:
                    results.add(normalized)
            page_state = str(data.get("next_page_state", "")).strip()
            if not page_state:
                return results

        if results:
            return results
        return await self._query_legacy(query)

    async def _query_legacy(self, query):
        results = set()
        next_url = f"{self.legacy_url}/{self.helpers.quote(query)}?l={self.limit}"

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
