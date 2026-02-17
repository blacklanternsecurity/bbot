from datetime import datetime
from urllib.parse import parse_qs, urlparse, urlunparse

from bbot.core.helpers.validators import clean_url
from bbot.modules.templates.subdomain_enum import subdomain_enum


class wayback(subdomain_enum):
    flags = ["passive", "subdomain-enum", "safe"]
    watched_events = ["DNS_NAME", "URL"]
    produced_events = ["URL_UNVERIFIED", "DNS_NAME", "WEB_PARAMETER"]
    meta = {
        "description": "Query archive.org's API for subdomains",
        "created_date": "2022-04-01",
        "author": "@liquidsec",
    }
    options = {"urls": False, "garbage_threshold": 10, "parameters": False}
    options_desc = {
        "urls": "emit URLs in addition to DNS_NAMEs",
        "garbage_threshold": "Dedupe similar urls if they are in a group of this size or higher (lower values == less garbage data)",
        "parameters": "emit WEB_PARAMETER events for query parameters discovered in archived URLs (requires urls=true)",
    }
    in_scope_only = True

    base_url = "http://web.archive.org"
    url_blacklist = ["_Incapsula_Resource"]

    async def setup(self):
        self.urls = self.config.get("urls", False)
        self.parameters = self.config.get("parameters", False)
        if self.parameters:
            if not self.urls:
                self.warning("parameters option requires urls to be enabled")
                return False
            consumers = [m for m, mod in self.scan.modules.items() if "WEB_PARAMETER" in mod.watched_events]
            if not consumers:
                self.warning("Disabling parameter extraction because no modules consume WEB_PARAMETER events")
                self.parameters = False
            else:
                self.hugeinfo(
                    f"Parameter extraction enabled because the following modules consume WEB_PARAMETER events: [{', '.join(consumers)}]"
                )
        self.garbage_threshold = self.config.get("garbage_threshold", 10)
        self._parameter_cache = {}
        return await super().setup()

    async def handle_event(self, event):
        if event.type == "URL":
            # use clean_url (always strips query) to match cache key regardless of url_querystring_remove setting
            cached = self._parameter_cache.pop(clean_url(event.data).geturl(), None)
            if cached is not None:
                flat_params, base_url = cached
                for param_name, original_value in flat_params.items():
                    data = {
                        "host": str(event.host),
                        "type": "GETPARAM",
                        "name": param_name,
                        "original_value": original_value,
                        "url": base_url,
                        "description": f"HTTP Extracted Parameter [{param_name}] (wayback)",
                        "additional_params": {k: v for k, v in flat_params.items() if k != param_name},
                    }
                    await self.emit_event(
                        data,
                        "WEB_PARAMETER",
                        event,
                        tags=["from-wayback"],
                        context=f"{{module}} found query parameter [{param_name}] in archived URL and emitted {{event.type}}",
                    )
            return

        query = self.make_query(event)
        for result, event_type in await self.query(query):
            tags = ["from-wayback"] if event_type == "URL_UNVERIFIED" else []
            await self.emit_event(
                result,
                event_type,
                event,
                tags=tags,
                abort_if=self.abort_if,
                context=f'{{module}} queried archive.org for "{query}" and found {{event.type}}: {{event.data}}',
            )

    async def query(self, query):
        results = set()
        waybackurl = f"{self.base_url}/cdx/search/cdx?url={self.helpers.quote(query)}&matchType=domain&output=json&fl=original&collapse=original"
        r = None
        for i in range(3):
            r = await self.helpers.request(waybackurl, timeout=self.http_timeout + 10)
            if r:
                break
            if i < 2:
                self.verbose(f'Error connecting to archive.org for query "{query}", retrying ({i + 1}/2)')
                await self.helpers.sleep(2**i)
        if not r:
            self.warning(f'Error connecting to archive.org for query "{query}"')
            return results
        try:
            j = r.json()
            assert type(j) == list
        except Exception:
            self.warning(f'Error JSON-decoding archive.org response for query "{query}"')
            return results

        urls = []
        for result in j[1:]:
            try:
                url = result[0]
                urls.append(url)
            except KeyError:
                continue

        self.verbose(f"Found {len(urls):,} URLs for {query}")

        # pre-extract parameters from raw URLs before collapse strips query strings
        raw_url_params = {}
        if self.parameters:
            for url in urls:
                try:
                    parsed = urlparse(url)
                    if any(bl in url for bl in self.url_blacklist):
                        continue
                    if parsed.query and parsed.hostname and self.scan.in_scope(parsed.hostname):
                        params = parse_qs(parsed.query)
                        flat_params = {k: v[0] for k, v in params.items()}
                        if flat_params:
                            # key by cleaned URL (always strips query) to match what collapse_urls produces
                            cleaned = clean_url(url)
                            cleaned_str = cleaned.geturl()
                            if cleaned_str not in raw_url_params:
                                raw_url_params[cleaned_str] = flat_params
                            else:
                                raw_url_params[cleaned_str].update(flat_params)
                except Exception:
                    continue

        dns_names = set()
        collapsed_urls = 0
        start_time = datetime.now()
        # we consolidate URLs to cut down on garbage data
        # this is CPU-intensive, so we do it in its own core.
        parsed_urls = await self.helpers.run_in_executor_mp(
            self.helpers.validators.collapse_urls,
            urls,
            threshold=self.garbage_threshold,
        )
        for parsed_url in parsed_urls:
            collapsed_urls += 1
            if not self.urls:
                dns_name = parsed_url.hostname
                h = hash(dns_name)
                if h not in dns_names:
                    dns_names.add(h)
                    results.add((dns_name, "DNS_NAME"))
            else:
                url_str = parsed_url.geturl()
                results.add((url_str, "URL_UNVERIFIED"))
                if self.parameters and url_str in raw_url_params:
                    base_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", ""))
                    self._parameter_cache[url_str] = (raw_url_params[url_str], base_url)
        end_time = datetime.now()
        duration = self.helpers.human_timedelta(end_time - start_time)
        self.verbose(f"Collapsed {len(urls):,} -> {collapsed_urls:,} URLs in {duration}")
        return results
