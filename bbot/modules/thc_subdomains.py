import re

from bbot.modules.base import BaseModule


class thc_subdomains(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["passive", "safe", "subdomain-enum"]
    meta = {
        "description": "Query ip.thc.org for subdomains",
        "created_date": "2026-02-19",
        "author": "@carlospolop",
    }
    options = {"limit": 100, "max_pages": 3}
    options_desc = {
        "limit": "Maximum results per API page",
        "max_pages": "Maximum number of API pages to fetch per query",
    }

    api_url = "https://ip.thc.org/lookup/subdomains"
    legacy_url = "https://ip.thc.org/sb"
    ansi_escape_re = re.compile(r"\x1b\[[0-9;]*m")

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
        for subdomain in sorted(results):
            if subdomain == event.data:
                continue
            if not subdomain.endswith(f".{query}"):
                continue
            try:
                subdomain = self.helpers.validators.validate_host(subdomain)
            except ValueError as exc:
                self.verbose(exc)
                continue
            await self.emit_event(
                subdomain,
                "DNS_NAME",
                event,
                context=f'{{module}} searched ip.thc.org subdomains for "{query}" and found {{event.type}}: {{event.data}}',
            )

    async def query(self, query):
        results = set()

        page_state = ""
        for _ in range(self.max_pages):
            body = {"domain": query, "page_state": page_state, "limit": self.limit}
            response = await self.helpers.request(self.api_url, method="POST", json=body)
            data = self._safe_json(response)
            subdomains = data.get("subdomains", [])
            if not isinstance(subdomains, list):
                break
            for entry in subdomains:
                if isinstance(entry, dict):
                    subdomain = str(entry.get("subdomain", "")).strip().rstrip(".")
                    if subdomain:
                        results.add(subdomain)
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
            for line in text.splitlines():
                clean = self.ansi_escape_re.sub("", line).strip()
                if not clean:
                    continue
                if clean.startswith(";;Next Page:"):
                    next_url = clean.split(":", 1)[1].strip()
                    continue
                if clean.startswith(";"):
                    continue
                hostname = clean.rstrip(".")
                if hostname:
                    results.add(hostname)
            if ";;Next Page:" not in text:
                break
        return results

    def _safe_json(self, response):
        if response is None:
            return {}
        if getattr(response, "status_code", 0) != 200:
            return {}
        try:
            data = response.json()
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        return {}
