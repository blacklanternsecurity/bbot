import time

from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class shodan_enterprise(BaseModule):
    """Shodan Enterprise API integration, batched.

    Design notes -- every number below was measured against a live Enterprise key
    (plan ``stream-100``, ``unlocked: True``) over 417 real target IPs:

    * ``/shodan/host/{ip}`` costs no query credits but is heavily rate limited.
      A token bucket lets a short burst through, then throttles hard: 2 req/s ran
      clean for 45s but produced 89x HTTP 429 across a 3.5-minute run. The
      sustained ceiling is ~1 req/s, so one request per in-scope IP is the thing
      that makes this module slow, not the network.

    * ``/shodan/host/search`` accepts an ``ip:`` filter holding a comma-separated
      list, returning many hosts per request. 800 IPs fit in one query; past that
      the URL exceeds the gateway's limit and returns 503. It costs 1 query credit
      per query plus 1 per extra page of 100 results.

    * The search index is NOT a drop-in replacement: it withholds some UDP
      banners. Across 106 hosts, 9 lost exactly ``53/udp`` -- and ``111/udp`` in an
      earlier sample -- while ``123/udp`` and ``5353/udp`` came through. No query
      shape recovers them (``transport:udp`` returns nothing at all). Since an
      exposed resolver is precisely the kind of finding this module exists to
      report, search cannot simply replace the host endpoint.

    So the module does both, in two phases. A batched search first asks which of
    these IPs Shodan knows anything about -- on real target sets only 15-25% of
    them do -- and then only those get a per-IP lookup for the full record. The
    result is identical to querying every IP individually, for a fraction of the
    requests: 417 IPs cost 5 searches + 106 lookups instead of 417 lookups.

    Set ``search_prefilter: false`` to skip phase 1 and look up every IP directly.
    That is slower but does not spend query credits, which matters on a plan
    where credits are metered.

    Both phases go through ``api_request()``, which does the rate limiting,
    retries and API key cycling, and sends a plain User-Agent rather than the
    scan's -- a browser User-Agent is what made Cloudflare challenge the search
    endpoint. Should a wall appear anyway, ``_search_known_ips`` turns the
    prefilter off after two failed chunks and the scan continues on direct
    lookups: slower, never wrong.
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

    # Collect IPs before querying so phase 1 has something worth batching.
    # BaseModule._events_waiting() drains whatever is queued rather than waiting
    # for a full batch, so small batches still arrive -- hence the buffer below.
    _batch_size = 100

    base_url = "https://api.shodan.io"

    # Consecutive failed search chunks before phase 1 gives up for this scan.
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

        # IPs seen across batches but not yet queried, plus every IP already
        # handled -- Shodan is queried at most once per address per scan.
        self._pending = []
        self._seen = set()
        self._parents = {}

        # Chunks whose search failed in a row. A wall in front of the search
        # endpoint -- a gateway, exhausted query credits -- should cost one or two
        # failed requests, not one per chunk for the rest of the scan.
        self._search_failures = 0

        if not self.config.get("in_scope_only", True):
            self.in_scope_only = False
            self.scope_distance_modifier = 1
            self.warning(
                "in_scope_only is disabled. This module will query IPs at distance 1 "
                "and may consume a lot of API credits!"
            )
        return True

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    async def _throttle(self):
        """Serialise requests to requests_per_second, across the whole module.

        Shodan's limit applies per API key, so the throttle has to sit in front of
        every request the module makes rather than inside any one worker. Each
        caller reserves the next free slot before its first await, so concurrent
        lookups queue up without a lock. This paces requests before they go out;
        api_request() handles the 429s that get through anyway.
        """
        now = time.monotonic()
        slot = max(now, self._next_slot)
        self._next_slot = slot + self._min_interval
        if slot > now:
            await self.helpers.sleep(slot - now)

    async def _get_json(self, url, description):
        """One API call: (parsed JSON body or None, HTTP status or 0).

        Rate limiting, retries and API key cycling are api_request()'s. A 404
        means Shodan has no data for that host -- a normal answer, not a failure.
        The status lets the search tell a rate limit from a wall.
        """
        # Once api_request() has errored the module out, every call returns
        # nothing; don't make each remaining IP wait its throttle slot for it.
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

        # Shodan explains refusals in the body ("Access denied", "Invalid
        # query", credit exhaustion). Logging only the status turns a
        # one-line fix into a guessing game.
        self.warning(f"Shodan API error for {description} (status {status_code}): {self._error_text(r)}")
        return None, status_code

    @staticmethod
    def _error_text(response):
        """Shodan's error message, trimmed, with the API key never echoed back."""
        body = (getattr(response, "text", "") or "").strip().replace("\n", " ")
        return body[:200] if body else "<empty body>"

    # Both builders leave "{api_key}" in place: api_request() substitutes the
    # current key on every attempt, so cycling after a 429 reaches the wire.
    def _host_url(self, ip):
        return f"{self.base_url}/shodan/host/{self.helpers.quote(ip)}?key={{api_key}}"

    def _search_url(self, query, page):
        # minify defaults to true server-side and strips the very fields this
        # module emits (cpe, http.components, vulns), so it is always disabled.
        return (
            f"{self.base_url}/shodan/host/search"
            f"?key={{api_key}}&minify=false&page={page}&query={self.helpers.quote(query)}"
        )

    # ------------------------------------------------------------------
    # batching
    # ------------------------------------------------------------------

    async def handle_batch(self, *events):
        """Queue incoming IPs, then query once the batch is worth sending.

        BaseModule hands over whatever is in the queue rather than waiting for
        batch_size events, so batches arrive in whatever size the scan produces.
        Buffering here keeps phase 1 efficient; finish() drains the remainder.
        """
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
        """Query whatever never reached a full batch.

        Called when the scan winds down. It can run more than once, which is safe
        here: _drain() empties _pending before awaiting anything.

        What finish() emits can lead back here -- a hostname resolves to an
        in-scope IP not seen before -- and those IPs are queued while the worker
        is busy in this method. Their wakeup is lost by the time the worker waits
        again (it does not re-check the queue first), so the scan would never
        finish. Take them off the queue and look them up before returning.
        """
        await self._drain()
        while self.num_incoming_events > 0:
            events, _ = await self._events_waiting()
            if events:
                await self.handle_batch(*events)
            await self._drain()

    async def _drain(self):
        batch, self._pending = self._pending, []
        if not batch:
            return
        try:
            await self._process(batch)
        finally:
            # _parents holds one event per IP, and through its parent chain the
            # whole graph above it. Nothing needs them once the batch is emitted,
            # and a scan that expands netblocks sees a lot of IPs.
            for ip in batch:
                self._parents.pop(ip, None)

    async def _process(self, ips):
        """Two-phase query: cheap batched search, then full per-IP lookups."""
        if self.search_prefilter:
            known = await self._search_known_ips(ips)
            skipped = len(ips) - len(known)
            searches = -(-len(ips) // self.search_chunk_size)  # ceil
            # info, not verbose: this is the line that says whether the prefilter
            # is earning its keep, and a big scan's verbose output gets buried.
            self.info(
                f"Shodan knows {len(known):,} of {len(ips):,} IPs; "
                f"{searches:,} search(es) + {len(known):,} lookup(s) "
                f"instead of {len(ips):,} lookups ({skipped:,} skipped)"
            )
        else:
            known = list(ips)

        if not known:
            return

        # The per-IP lookup is what makes the result complete: the search index
        # withholds UDP banners (53/udp, 111/udp) that this endpoint returns.
        lookups = (self._lookup_and_emit(ip) for ip in known)
        async for _ in self.helpers.as_completed(lookups, max_concurrent=self.concurrency):
            pass

    async def _search_known_ips(self, ips):
        """Phase 1: which of these IPs does Shodan have anything on?

        One request per search_chunk_size IPs. Only the ip_str of each match is
        used -- the banners themselves are re-fetched per host in phase 2, since
        the search copy is incomplete.

        A chunk whose search fails is returned whole, so a failure costs speed and
        never findings. After _max_search_failures chunks fail in a row the
        prefilter turns itself off for the rest of the scan: a wall in front of
        this endpoint should cost two requests, not one per chunk.
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
                        # nothing more will get through; the lookups would be skipped too
                        return known
                    # A failed search must not silently drop these IPs; fall back
                    # to looking the whole chunk up directly.
                    self.verbose(f"Search failed for a chunk of {len(chunk)} IPs; falling back to direct lookups")
                    found = chunk_set
                    # A rate limit says the key is busy, not that search is
                    # unavailable: it must not count toward turning phase 1 off,
                    # which would multiply the requests sent to that same key.
                    rate_limited = status_code == 429
                    failed = not rate_limited
                    break

                matches = body.get("matches") or []
                for match in matches:
                    ip = match.get("ip_str")
                    if ip in chunk_set:
                        found.add(ip)

                # Every IP in the chunk is accounted for. Search bills a query
                # credit per page and returns one match per banner, not per host,
                # so a chunk of busy hosts runs to many pages -- and every page
                # past this one is a credit spent to re-learn what we know.
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
                # whatever is left in this batch skips phase 1 too
                known.extend(ips[start + self.search_chunk_size :])
                break

        return known

    async def _lookup_and_emit(self, ip):
        """Phase 2: the complete host record, and the events that come from it."""
        host, _ = await self._get_json(self._host_url(ip), ip)
        if host is None:
            return
        if "data" not in host:
            self.debug(f"No Shodan data about {ip}")
            return
        await self._emit_host(ip, host)

    # ------------------------------------------------------------------
    # emitting
    # ------------------------------------------------------------------

    async def _emit_host(self, ip, host):
        event = self._parents.get(ip)
        if event is None:
            return

        # TECHNOLOGY carries no port (see _emit_technology), so the same technology
        # on two banners is the same event -- and letting BBOT dedup them means
        # whichever copy happens to arrive first decides the parent. Emit each one
        # once, from the first banner that reports it, so the parent is stable.
        emitted_technologies = set()
        for data in host["data"]:
            port_event = await self._emit_ports(ip, data, event)
            parent = port_event or event
            await self._emit_technologies(ip, data, parent, emitted_technologies)
            await self._emit_findings(ip, data, parent)

    async def _emit_technology(self, ip, technology, data, event, tags, emitted, cpe=None):
        # TECHNOLOGY has no port field. The validator lowercases, so dedup on that form.
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
        """Emit the banner's open port, and return it so it can parent the rest."""
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
        # Name the affected service in the finding itself. Shodan attaches a vuln
        # to one banner, so a host running the same product on 80 and 443 reports
        # the CVE twice -- and with the port recorded only in the parent chain the
        # two findings are byte-identical, so BBOT dedups them and the second
        # service vanishes from the report. FINDING's validator takes a fixed
        # field set with no port in it, so the service goes in "description".
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
                # FINDING's validator accepts a fixed set of fields and silently
                # drops the rest, so the CVE goes in "cves", the field meant for
                # it, and not only as free text in "description". Matches how
                # shodan_idb reports the same kind of finding.
                "cves": [cve],
            }
            # No "host" here on purpose: ClosestHostEvent takes host *and* port
            # from the closest parent only when the finding declares no host of
            # its own. The parent is the banner's port event (or the IP when the
            # banner has no port), so event.port names the service and
            # consumers that read it, like output/nmap_xml.py, get it right.
            await self.emit_event(
                vuln,
                "FINDING",
                parent=event,
                tags=[],
                context=f"{{module}} queried Shodan API for {ip} and found FINDING {cve}{service}",
            )
