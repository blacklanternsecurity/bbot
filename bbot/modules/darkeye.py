import re
import unicodedata

from bbot.core.config.models import BaseModuleConfig, Field
from bbot.modules.templates.subdomain_enum import subdomain_enum


class darkeye(subdomain_enum):
    watched_events = ["DNS_NAME"]
    produced_events = ["FINDING"]
    flags = ["safe", "passive"]
    meta = {
        "description": "Query DarkEye (Have I Been Ransomed? and Breach House) for ransomware leaks, data breaches, access leads and stealer logs tied to a domain",
        "created_date": "2026-10-23",
        "author": "@juanmill4",
    }

    class Config(BaseModuleConfig):
        haveibeenransom_api_key: str = Field(
            "",
            description="Have I Been Ransomed? API token. Set this, breachhouse_api_key, or both",
            sensitive=True,
        )
        breachhouse_api_key: str = Field(
            "",
            description="Breach House API token. Set this, haveibeenransom_api_key, or both",
            sensitive=True,
        )
        max_pages: int = Field(
            5,
            description="Maximum pages of Have I Been Ransomed? results (20 leaks each) to request per domain. Each page counts as one request against the token's daily quota",
        )
        limit: int = Field(
            25,
            description="Maximum Breach House results per source (ransomware, breaches, leads, stealers) per domain, up to 200. Each domain is one request",
        )

    target_only = True

    hibr_name = "Have I Been Ransomed?"
    hibr_url = "https://haveibeenransom.com/api/metadata/domain"
    breachhouse_name = "Breach House"
    breachhouse_url = "https://breach.house/api/v1/search"
    breachhouse_max_limit = 200

    # the APIs treat * and ? as wildcards, so only plain domain names are queried
    domain_regex = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")

    # category: (finding name, severity, description label)
    categories = {
        "ransomware": ("Ransomware Leak", "MEDIUM", "ransomware leak-site post"),
        "breaches": ("Data Breach", "LOW", "data breach"),
        "leads": ("Access Lead", "MEDIUM", "access lead"),
        "stealers": ("Stealer Log", "MEDIUM", "stealer log"),
    }
    hibr_categories = {"ransomware_leak": "ransomware", "traditional_breach": "breaches"}

    async def setup(self):
        self.hibr_key = self.config.get("haveibeenransom_api_key", "")
        self.breachhouse_key = self.config.get("breachhouse_api_key", "")
        if not (self.hibr_key or self.breachhouse_key):
            return None, "No API key set (haveibeenransom_api_key or breachhouse_api_key)"
        self.max_pages = max(1, int(self.config.get("max_pages", 5)))
        self.limit = min(max(1, int(self.config.get("limit", 25))), self.breachhouse_max_limit)
        return await super().setup()

    async def handle_event(self, event):
        query = self.make_query(event).lower()
        if not self.domain_regex.match(query):
            self.debug(f"Skipping {query}: not a plain domain name")
            return
        seen = set()
        for product, records in (
            (self.hibr_name, self.query_hibr(query) if self.hibr_key else None),
            (self.breachhouse_name, self.query_breachhouse(query) if self.breachhouse_key else None),
        ):
            if records is None:
                continue
            async for category, record in records:
                title = self.clean(record.get("post_title")) or self.clean(record.get("website"))
                if not title:
                    continue
                source = self.clean(record.get("group_name"))
                discovered = self.clean(record.get("discovered"))[:10]
                # both products can list the same ransomware victim or breach, so it's reported once
                key = (category, title.lower(), source.lower(), discovered)
                if key in seen:
                    continue
                seen.add(key)
                name, severity, label = self.categories.get(category, ("Data Leak", "LOW", "data leak"))
                description = f"DarkEye {label} ({product}): {title}"
                if source:
                    description += f" (source: {source})"
                if discovered:
                    description += f", discovered {discovered}"
                # HIBR matches the domain exactly; Breach House is a text search, so a record whose
                # website is another domain only mentions the target
                website = self.clean(record.get("website")).lower()
                matches = product == self.hibr_name or website == query or website.endswith(f".{query}")
                await self.emit_event(
                    {
                        "host": query,
                        "name": name,
                        "description": description,
                        "severity": severity,
                        "confidence": "MEDIUM" if matches else "LOW",
                    },
                    "FINDING",
                    parent=event,
                    context=f'{{module}} searched DarkEye ({product}) for "{query}" and found {{event.type}}: {description}',
                )

    async def request_json(self, product, url, api_key, domain):
        r = await self.api_request(url, headers={"Authorization": f"Bearer {api_key}"})
        status_code = getattr(r, "status_code", 0)
        if status_code != 200:
            self.warning(f"Error querying {product} for {domain} (status code {status_code})")
            return None
        try:
            j = r.json()
        except Exception:
            self.warning(f"Invalid JSON from {product} for {domain}")
            return None
        if not isinstance(j, dict):
            self.warning(f"Unexpected response from {product} for {domain}")
            return None
        return j

    async def query_hibr(self, domain):
        seen = set()
        for page in range(1, self.max_pages + 1):
            url = f"{self.hibr_url}/{domain}" if page == 1 else f"{self.hibr_url}/{domain}/{page}"
            j = await self.request_json(self.hibr_name, url, self.hibr_key, domain)
            if j is None:
                return
            # the API returns "sources" and a top-level "has_next"; its docs show "results" and "pagination"
            pagination = j.get("pagination") if isinstance(j.get("pagination"), dict) else {}
            for leak in j.get("sources") or j.get("results") or []:
                if not isinstance(leak, dict):
                    continue
                # the same leak can be repeated on a later page if it was indexed while paging
                leak_id = str(leak.get("id_source") or leak.get("id") or "")
                if not leak_id or leak_id in seen:
                    continue
                seen.add(leak_id)
                yield self.hibr_categories.get(leak.get("leak_type"), ""), leak
            # a page can be short or empty and still have a next page, so only has_next ends the search
            if not j.get("has_next", pagination.get("has_next", False)):
                return
        self.info(
            f"{domain} has more results in {self.hibr_name} than max_pages={self.max_pages} allows. Raise max_pages to get the rest"
        )

    async def query_breachhouse(self, domain):
        url = f"{self.breachhouse_url}?q={domain}&limit={self.limit}"
        j = await self.request_json(self.breachhouse_name, url, self.breachhouse_key, domain)
        if j is None:
            return
        truncated = False
        for category in self.categories:
            # each source is {"results": [...], "total": n}
            source = j.get(category)
            if isinstance(source, dict):
                items = source.get("results")
                total = source.get("total")
            else:
                items, total = source, None
            if not isinstance(items, list):
                continue
            if total > len(items) if isinstance(total, int) else len(items) >= self.limit:
                truncated = True
            for item in items:
                if isinstance(item, dict):
                    yield category, item
        if truncated:
            self.info(
                f"{domain} has more results in {self.breachhouse_name} than limit={self.limit} allows. Raise limit (up to {self.breachhouse_max_limit}) to get the rest"
            )

    @staticmethod
    def clean(value):
        # some source names use styled Unicode characters and irregular spacing
        if not isinstance(value, str):
            return ""
        return " ".join(unicodedata.normalize("NFKC", value).split())
