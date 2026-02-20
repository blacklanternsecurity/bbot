import re

from bbot.modules.base import BaseModule


class thc_rdns(BaseModule):
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
    ansi_escape_re = re.compile(r"\x1b\[[0-9;]*m")

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
