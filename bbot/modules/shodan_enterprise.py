import time

from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class shodan_enterprise(BaseModule):
    """Shodan Enterprise API integration. Batches IPs through a count prefilter, then looks up each known host.

    The prefilter uses /shodan/host/count, which spends no query credits. Set ``search_prefilter: false``
    to skip it and look up every IP directly.
    """

    watched_events = ["IP_ADDRESS"]
    produced_events = ["OPEN_TCP_PORT", "TECHNOLOGY", "OPEN_UDP_PORT", "FINDING", "DNS_NAME"]
    flags = ["safe", "passive"]
    meta = {
        "created_date": "2026-01-27",
        "author": "@Control-Punk-Delete, @Tsybon",
        "description": "Query the Shodan Enterprise API for open ports, technologies, vulnerabilities and hostnames",
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
                "Use a batched count query (no query credits) to find which IPs Shodan knows "
                "before looking them up individually. If false, every IP is looked up."
            ),
        )
        search_chunk_size: int = Field(
            100, description="IPs per batched count query (hard ceiling is ~800 before the URL is rejected)"
        )
        concurrency: int = Field(
            4, description="Max in-flight API requests. The rate limit, not this, is usually the constraint."
        )

    in_scope_only = True

    _batch_size = 100

    base_url = "https://api.shodan.io"

    # consecutive failed count queries before the prefilter is disabled for the scan
    _max_search_failures = 2

    # NIST CVSS score -> severity, as in shodan_idb; below 0.1 or unknown is INFO
    _cvss_severity_thresholds = (
        (9.0, "CRITICAL"),
        (7.0, "HIGH"),
        (4.0, "MEDIUM"),
        (0.1, "LOW"),
    )

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

        # count queries that failed in a row
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
        """Shodan's error message, trimmed."""
        body = (getattr(response, "text", "") or "").strip().replace("\n", " ")
        return body[:200] if body else "<empty body>"

    # "{api_key}" is left for api_request() to substitute, so key cycling works on retries
    def _host_url(self, ip):
        return f"{self.base_url}/shodan/host/{self.helpers.quote(ip)}?key={{api_key}}"

    def _count_url(self, ips):
        # an ip facet as large as the chunk lists every known IP in one answer
        query = self.helpers.quote("ip:" + ",".join(ips))
        facets = self.helpers.quote(f"ip:{len(ips)}")
        return f"{self.base_url}/shodan/host/count?key={{api_key}}&query={query}&facets={facets}"

    async def handle_batch(self, *events):
        """Count query to find known IPs, then a full lookup of each."""
        # incoming events are already deduplicated by the base module
        parents = {str(event.data): event for event in events}
        ips = list(parents)

        # a count plus a lookup costs more than the lookup alone
        if self.search_prefilter and len(ips) > 1:
            known = await self._known_ips(ips)
            skipped = len(ips) - len(known)
            counts = -(-len(ips) // self.search_chunk_size)  # ceil
            self.info(
                f"Shodan knows {len(known):,} of {len(ips):,} IPs; "
                f"{counts:,} count query(ies) + {len(known):,} lookup(s) "
                f"instead of {len(ips):,} lookups ({skipped:,} skipped)"
            )
        else:
            known = ips

        # the count query only says which IPs are known; banners, vulns and hostnames come from the lookup
        lookups = (self._lookup_and_emit(ip, parents[ip]) for ip in known)
        async for _ in self.helpers.as_completed(lookups, max_concurrent=self.concurrency):
            pass

    async def _known_ips(self, ips):
        """Return the IPs Shodan knows about, one count query per search_chunk_size IPs.

        A chunk whose count query fails is returned whole, so a failure costs speed, never findings.
        After _max_search_failures failed chunks in a row the prefilter is disabled for the scan.
        """
        known = []
        for start in range(0, len(ips), self.search_chunk_size):
            chunk = ips[start : start + self.search_chunk_size]
            body, status_code = await self._get_json(self._count_url(chunk), f"count of {len(chunk)} IPs")

            if body is not None:
                facets = (body.get("facets") or {}).get("ip") or []
                found = {str(facet.get("value")) for facet in facets if isinstance(facet, dict)}
                known.extend(ip for ip in chunk if ip in found)
                self._search_failures = 0
                continue

            if self.errored:
                return known
            # fall back to direct lookups of the whole chunk
            self.verbose(f"Count query failed for a chunk of {len(chunk)} IPs; falling back to direct lookups")
            known.extend(chunk)

            # a rate limit does not count toward disabling the prefilter
            if status_code == 429:
                continue
            self._search_failures += 1
            if self._search_failures >= self._max_search_failures:
                self.warning(
                    f"Count query failed {self._search_failures} times in a row; disabling search_prefilter for "
                    "the rest of the scan and querying every IP directly. Slower, same results."
                )
                self.search_prefilter = False
                known.extend(ips[start + self.search_chunk_size :])
                break

        return known

    async def _lookup_and_emit(self, ip, event):
        """Look up the full host record and emit its events."""
        host, _ = await self._get_json(self._host_url(ip), ip)
        if host is None:
            return
        if not host.get("data") and not host.get("hostnames"):
            self.debug(f"No Shodan data about {ip}")
            return
        await self._emit_host(ip, host, event)

    async def _emit_host(self, ip, host, event):
        await self._emit_hostnames(ip, host, event)

        # TECHNOLOGY has no port, so emit each one once, from the first banner that reports it
        emitted_technologies = set()
        for data in host.get("data") or []:
            # the port event is the parent of everything found in that banner
            port_event = await self._emit_ports(ip, data, event)
            parent = port_event or event
            await self._emit_technologies(ip, data, parent, emitted_technologies)
            await self._emit_findings(ip, data, parent)

    async def _emit_hostnames(self, ip, host, event):
        # reverse DNS and certificate names Shodan has seen on this IP (the host-level list only)
        seen = set()
        for hostname in host.get("hostnames") or []:
            name = str(hostname).strip().rstrip(".").lower()
            # skip wildcards: the DNS_NAME validator would turn them into the parent domain
            if not name or name == ip or "*" in name or name in seen:
                continue
            seen.add(name)
            await self.emit_event(
                name,
                "DNS_NAME",
                parent=event,
                context=f"{{module}} queried Shodan API for {ip} and found {{event.type}}: {{event.pretty_string}}",
            )

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
            score = self._cvss_score(vuln_data)
            # FINDING rejects anything but INFO..CRITICAL, so an unscored CVE is INFO rather than dropped
            severity = self._cvss_to_severity(score) or "INFO"
            cvss = f" (CVSS {score:.1f})" if score is not None else ""
            vuln = {
                "name": "Shodan - Possible Vulnerabilities",
                "severity": severity,
                "description": f"{cve}{service}{cvss}",
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

    @staticmethod
    def _cvss_score(vuln_data):
        """The first numeric score of cvss_v3, cvss and cvss_v2, or None."""
        if not isinstance(vuln_data, dict):
            return None
        for key in ("cvss_v3", "cvss", "cvss_v2"):
            value = vuln_data.get(key)
            if value is None:
                continue
            try:
                return float(value)
            except (TypeError, ValueError):
                return None
        return None

    @classmethod
    def _cvss_to_severity(cls, score):
        if score is None:
            return None
        for threshold, label in cls._cvss_severity_thresholds:
            if score >= threshold:
                return label
        return None
