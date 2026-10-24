import time

from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class shodan_enterprise(BaseModule):
    """Shodan Enterprise API integration. Batches IPs through a search prefilter, then looks up each known host.

    Set ``search_prefilter: false`` to look up every IP directly without spending query credits.
    """

    watched_events = ["IP_ADDRESS"]
    produced_events = ["OPEN_TCP_PORT", "TECHNOLOGY", "OPEN_UDP_PORT", "FINDING"]
    flags = ["safe", "passive"]
    meta = {
        "created_date": "2026-01-27",
        "author": "@Control-Punk-Delete, @Tsybon",
        "description": "Shodan Enterprise API integration module.",
    }

    class Config(BaseModuleConfig):
        api_key: str | list[str] = Field("", description="Shodan API Key", sensitive=True, mandatory=True)
        in_scope_only: bool = Field(
            True, description="Only query in-scope IPs. If False, will query up to distance 1."
        )
        requests_per_second: float = Field(
            1.0, description="Max API requests per second. Measured sustained ceiling is ~1/s."
        )
        search_prefilter: bool = Field(
            True,
            description=(
                "Use a batched search to find which IPs Shodan knows before looking them up "
                "individually. Far fewer requests; costs query credits."
            ),
        )
        search_chunk_size: int = Field(
            100, description="IPs per batched search query (hard ceiling is ~800 before the URL is rejected)"
        )
        concurrency: int = Field(
            4, description="Max in-flight API requests. The rate limit, not this, is usually the constraint."
        )

    in_scope_only = True

    # IPs are buffered in handle_batch() until a full batch is worth querying
    _batch_size = 100

    base_url = "https://api.shodan.io"

    # consecutive failed search chunks before the prefilter is disabled for the scan
    _max_search_failures = 2

    # NIST CVSS score -> severity
    severity_map = {"NONE": 0.0, "LOW": 0.1, "MEDIUM": 4.0, "HIGH": 7.0, "CRITICAL": 9.0}

    async def setup(self):
        self.api_key = self.config.get("api_key", "")
        if not self.api_key:
            return None, "No API key specified"

        self.requests_per_second = max(float(self.config.get("requests_per_second", 1.0)), 0.01)
        self.search_prefilter = bool(self.config.get("search_prefilter", True))
        self.search_chunk_size = max(int(self.config.get("search_chunk_size", 100)), 1)

        self.concurrency = max(int(self.config.get("concurrency", 4)), 1)
        self._next_slot = 0.0
        self._min_interval = 1.0 / self.requests_per_second

        # Shodan is queried at most once per address per scan
        self._pending = []
        self._seen = set()
        self._parents = {}

        # search chunks that failed in a row
        self._search_failures = 0

        if not self.config.get("in_scope_only", True):
            self.in_scope_only = False
            self.scope_distance_modifier = 1
            self.warning(
                "in_scope_only is disabled. This module will query IPs at distance 1 "
                "and may consume a lot of API credits!"
            )
        return True

    async def _throttle(self):
        """Pace requests to requests_per_second across the whole module (the limit is per API key)."""
        now = time.monotonic()
        slot = max(now, self._next_slot)
        self._next_slot = slot + self._min_interval
        if slot > now:
            await self.helpers.sleep(slot - now)

    async def _get_json(self, url, description):
        """One API call: (parsed JSON body or None, HTTP status or 0). A 404 is a normal "no data" answer."""
        # once api_request() has errored the module out, skip the throttle wait
        if self.errored:
            return None, 0
        await self._throttle()
        r = await self.api_request(url)

        if r is None:
            self.debug(f"No response from Shodan for {description}")
            return None, 0

        status_code = getattr(r, "status_code", 0)
        if status_code == 404:
            self.debug(f"No Shodan data about {description}")
            return None, status_code

        if getattr(r, "is_success", False):
            try:
                return r.json(), status_code
            except Exception as e:
                self.warning(f"Failed to parse Shodan response for {description}: {e}")
                return None, status_code

        # Shodan explains refusals in the body, so log it
        self.warning(f"Shodan API error for {description} (status {status_code}): {self._error_text(r)}")
        return None, status_code

    @staticmethod
    def _error_text(response):
        """Shodan's error message, trimmed, with the API key never echoed back."""
        body = (getattr(response, "text", "") or "").strip().replace("\n", " ")
        return body[:200] if body else "<empty body>"

    # "{api_key}" is left for api_request() to substitute, so key cycling works on retries
    def _host_url(self, ip):
        return f"{self.base_url}/shodan/host/{self.helpers.quote(ip)}?key={{api_key}}"

    def _search_url(self, query, page):
        # minify=false: the default strips cpe, http.components and vulns
        return (
            f"{self.base_url}/shodan/host/search"
            f"?key={{api_key}}&minify=false&page={page}&query={self.helpers.quote(query)}"
        )

    async def handle_batch(self, *events):
        """Buffer incoming IPs and query once there are batch_size of them; finish() drains the rest."""
        for event in events:
            ip = str(event.data)
            if ip in self._seen:
                continue
            self._seen.add(ip)
            self._pending.append(ip)
            self._parents[ip] = event

        if len(self._pending) >= self.batch_size:
            await self._drain()

    async def finish(self):
        await self._drain()

    async def _drain(self):
        batch, self._pending = self._pending, []
        if not batch:
            return
        try:
            await self._process(batch)
        finally:
            # release the events, and the graph above them, once the batch is emitted
            for ip in batch:
                self._parents.pop(ip, None)

    async def _process(self, ips):
        """Batched search to find known IPs, then a full lookup of each."""
        if self.search_prefilter:
            known = await self._search_known_ips(ips)
            skipped = len(ips) - len(known)
            searches = -(-len(ips) // self.search_chunk_size)  # ceil
            self.info(
                f"Shodan knows {len(known):,} of {len(ips):,} IPs; "
                f"{searches:,} search(es) + {len(known):,} lookup(s) "
                f"instead of {len(ips):,} lookups ({skipped:,} skipped)"
            )
        else:
            known = list(ips)

        if not known:
            return

        # the search index withholds some UDP banners, so the per-IP lookup is what completes the result
        lookups = (self._lookup_and_emit(ip) for ip in known)
        async for _ in self.helpers.as_completed(lookups, max_concurrent=self.concurrency):
            pass

    async def _search_known_ips(self, ips):
        """Return the IPs Shodan knows about, one search per search_chunk_size IPs.

        A chunk whose search fails is returned whole, so a failure costs speed, never findings.
        After _max_search_failures failed chunks in a row the prefilter is disabled for the scan.
        """
        known = []
        for start in range(0, len(ips), self.search_chunk_size):
            chunk = ips[start : start + self.search_chunk_size]
            query = "ip:" + ",".join(chunk)
            chunk_set = set(chunk)
            found = set()
            failed = False
            rate_limited = False
            page = 1

            while True:
                body, status_code = await self._get_json(self._search_url(query, page), f"search of {len(chunk)} IPs")
                if body is None:
                    if self.errored:
                        return known
                    # fall back to direct lookups of the whole chunk
                    self.verbose(f"Search failed for a chunk of {len(chunk)} IPs; falling back to direct lookups")
                    found = chunk_set
                    # a rate limit does not count toward disabling the prefilter
                    rate_limited = status_code == 429
                    failed = not rate_limited
                    break

                matches = body.get("matches") or []
                for match in matches:
                    ip = match.get("ip_str")
                    if ip in chunk_set:
                        found.add(ip)

                # every page costs a query credit, so stop once the whole chunk is accounted for
                if found == chunk_set:
                    break

                total = body.get("total")
                if len(matches) < 100 or (isinstance(total, int) and page * 100 >= total):
                    break
                page += 1

            known.extend(ip for ip in chunk if ip in found)

            if rate_limited:
                continue
            if not failed:
                self._search_failures = 0
                continue

            self._search_failures += 1
            if self._search_failures >= self._max_search_failures:
                self.warning(
                    f"Search failed {self._search_failures} times in a row; disabling search_prefilter for the "
                    "rest of the scan and querying every IP directly. Slower, same results."
                )
                self.search_prefilter = False
                known.extend(ips[start + self.search_chunk_size :])
                break

        return known

    async def _lookup_and_emit(self, ip):
        """Look up the full host record and emit its events."""
        host, _ = await self._get_json(self._host_url(ip), ip)
        if host is None:
            return
        if "data" not in host:
            self.debug(f"No Shodan data about {ip}")
            return
        await self._emit_host(ip, host)

    async def _emit_host(self, ip, host):
        event = self._parents.get(ip)
        if event is None:
            return

        # TECHNOLOGY has no port, so emit each one once, from the first banner that reports it
        emitted_technologies = set()
        for data in host["data"]:
            # the port event is the parent of everything found in that banner
            port_event = await self._emit_ports(ip, data, event)
            parent = port_event or event
            await self._emit_technologies(ip, data, parent, emitted_technologies)
            await self._emit_findings(ip, data, parent)

    async def _emit_technology(self, ip, technology, data, event, tags, emitted, cpe=None):
        # the validator lowercases, so dedup on that form
        key = str(technology).lower()
        if key in emitted:
            return
        emitted.add(key)

        tech = {"technology": technology, "host": data.get("ip_str")}
        if cpe is not None:
            tech["cpe"] = cpe
        await self.emit_event(
            tech,
            "TECHNOLOGY",
            parent=event,
            tags=tags,
            context=f"{{module}} queried Shodan API for {ip} and found TECHNOLOGY: {technology}",
        )

    async def _emit_technologies(self, ip, data, event, emitted):
        tags = data.get("tags") or []

        # name technologies by CPE product (raw CPE kept in "cpe"), falling back to Shodan's product name
        named = False
        for cpe in data.get("cpe23") or data.get("cpe") or []:
            technology = self.helpers.cpe_product(cpe)
            if technology is not None:
                named = True
                await self._emit_technology(ip, technology, data, event, tags, emitted, cpe=cpe)
        if not named and "product" in data:
            await self._emit_technology(ip, data["product"], data, event, tags, emitted)

        components = (data.get("http") or {}).get("components") or {}
        for technology, details in components.items():
            component_tags = list((details or {}).get("categories", []))
            component_tags.append("web-technology")
            await self._emit_technology(ip, technology, data, event, component_tags, emitted)

    async def _emit_ports(self, ip, data, event):
        """Emit the banner's open port and return it."""
        if "port" not in data or "transport" not in data:
            return None

        transport = data["transport"]
        event_type = {"tcp": "OPEN_TCP_PORT", "udp": "OPEN_UDP_PORT"}.get(transport)
        if event_type is None:
            self.warning(f"Unknown transport {transport}")
            return None

        return await self.emit_event(
            self.helpers.make_netloc(ip, data.get("port")),
            event_type,
            parent=event,
            tags=data.get("tags") or [],
            context=f"{{module}} queried Shodan API for {ip} and found {event_type}: {data.get('port')}",
        )

    async def _emit_findings(self, ip, data, event):
        # the service goes in "description" so the same CVE on two ports is not deduped into one finding
        port = data.get("port")
        transport = data.get("transport")
        service = f" on {port}/{transport}" if port is not None and transport else ""

        for cve, vuln_data in (data.get("vulns") or {}).items():
            cvss = vuln_data.get("cvss", 0)
            severity = max(
                (level for level, threshold in self.severity_map.items() if cvss >= threshold),
                key=lambda x: self.severity_map[x],
            )
            vuln = {
                "name": "Shodan - Possible Vulnerabilities",
                "severity": severity,
                "description": f"{cve}{service}",
                "confidence": "LOW",
                "cves": [cve],
            }
            # no "host": FINDING then takes host and port from its parent, the banner's port event
            await self.emit_event(
                vuln,
                "FINDING",
                parent=event,
                tags=[],
                context=f"{{module}} queried Shodan API for {ip} and found FINDING {cve}{service}",
            )
