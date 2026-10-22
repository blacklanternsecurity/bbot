import re
import unicodedata

from bbot.core.config.models import BaseModuleConfig, Field
from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class haveibeenransom(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["FINDING"]
    flags = ["safe", "passive"]
    meta = {
        "description": "Query Have I Been Ransomed? for ransomware leak-site posts and data breaches tied to a domain",
        "created_date": "2026-10-23",
        "author": "@juanmill4",
    }

    class Config(BaseModuleConfig):
        api_key: str | list[str] = Field(
            "", description="Have I Been Ransomed? API token", sensitive=True, mandatory=True
        )
        max_pages: int = Field(
            5,
            description="Maximum pages of results (20 leaks each) to request per domain. Each page counts as one request against the token's daily quota",
        )

    target_only = True

    base_url = "https://haveibeenransom.com/api/metadata/domain"

    # the API treats * and ? as wildcards, so only plain domain names are queried
    domain_regex = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")

    leak_types = {
        "ransomware_leak": ("Ransomware Leak", "MEDIUM", "Ransomware leak-site post"),
        "traditional_breach": ("Data Breach", "LOW", "Data breach"),
    }

    async def setup(self):
        self.max_pages = max(1, int(self.config.get("max_pages", 5)))
        return await super().setup()

    async def handle_event(self, event):
        query = self.make_query(event).lower()
        if not self.domain_regex.match(query):
            self.debug(f"Skipping {query}: not a plain domain name")
            return
        seen = set()
        async for leak in self.query_leaks(query):
            # the same leak can be repeated on a later page if it was indexed while paging
            leak_id = str(leak.get("id_source") or leak.get("id") or "")
            if not leak_id or leak_id in seen:
                continue
            seen.add(leak_id)
            title = self.clean(leak.get("post_title")) or self.clean(leak.get("website"))
            if not title:
                continue
            source = self.clean(leak.get("group_name"))
            discovered = self.clean(leak.get("discovered"))[:10]
            name, severity, label = self.leak_types.get(leak.get("leak_type"), ("Data Leak", "LOW", "Data leak"))
            description = f"{label}: {title}"
            if source:
                description += f" (source: {source})"
            if discovered:
                description += f", discovered {discovered}"
            await self.emit_event(
                {
                    "host": query,
                    "name": name,
                    "description": description,
                    "severity": severity,
                    "confidence": "MEDIUM",
                },
                "FINDING",
                parent=event,
                context=f'{{module}} searched Have I Been Ransomed? for "{query}" and found {{event.type}}: {description}',
            )

    async def query_leaks(self, domain):
        for page in range(1, self.max_pages + 1):
            url = f"{self.base_url}/{domain}" if page == 1 else f"{self.base_url}/{domain}/{page}"
            r = await self.api_request(url)
            status_code = getattr(r, "status_code", 0)
            if status_code != 200:
                self.warning(f"Error querying Have I Been Ransomed? for {domain} (status code {status_code})")
                return
            try:
                j = r.json()
            except Exception:
                self.warning(f"Invalid JSON from Have I Been Ransomed? for {domain}")
                return
            if not isinstance(j, dict):
                self.warning(f"Unexpected response from Have I Been Ransomed? for {domain}")
                return
            # the API returns "sources" and a top-level "has_next"; its docs show "results" and "pagination"
            pagination = j.get("pagination") if isinstance(j.get("pagination"), dict) else {}
            for leak in j.get("sources") or j.get("results") or []:
                if isinstance(leak, dict):
                    yield leak
            # a page can be short or empty and still have a next page, so only has_next ends the search
            if not j.get("has_next", pagination.get("has_next", False)):
                return
        self.info(
            f"{domain} has more results in Have I Been Ransomed? than max_pages={self.max_pages} allows. Raise max_pages to get the rest"
        )

    @staticmethod
    def clean(value):
        # some source names use styled Unicode characters and irregular spacing
        if not isinstance(value, str):
            return ""
        return " ".join(unicodedata.normalize("NFKC", value).split())
