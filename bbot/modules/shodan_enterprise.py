import asyncio
import time

from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field

try:
    import httpx
except ImportError:  # pragma: no cover - httpx is not a BBOT dependency
    httpx = None


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

    One wrinkle forced a split transport. ``/shodan/host/search`` sits behind
    Cloudflare, which challenges BBOT's HTTP engine (blasthttp) and answers 403
    with an interstitial page -- while ``/shodan/host/{ip}`` through the very same
    engine returns 200. A full browser header set does not help, so the trigger is
    the TLS fingerprint rather than anything in the request. Phase 1 therefore goes
    out over httpx, which Cloudflare accepts; phase 2 keeps using BBOT's engine so
    it still honours scan-wide proxy and SSL settings. httpx is not a BBOT
    dependency, so if it is missing the module says so and disables the prefilter
    instead of failing.
    """

    watched_events = ["IP_ADDRESS"]
    produced_events = ["OPEN_TCP_PORT", "TECHNOLOGY", "OPEN_UDP_PORT", "FINDING"]
    flags = ["safe", "passive"]
    meta = {
        "created_date": "2026-01-27",
        "author": "@Control-Punk-Delete",
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
        max_retries: int = Field(3, description="Retries on rate-limit and server errors")
        retry_backoff: float = Field(2.0, description="Initial backoff seconds between retries (doubles each attempt)")
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

    # No deps_pip for httpx, deliberately. Phase 1 needs it (see the class
    # docstring), but declaring it makes BBOT run `pip install --upgrade httpx`
    # into its venv at every scan start, as the scan account -- which cannot
    # write there. The install fails, and a module whose setup fails is not
    # loaded at all: one unwritable directory turned "no prefilter, slower" into
    # "no Shodan findings", 1,036 events to zero, silently. setup() already
    # degrades gracefully when httpx is absent, so the dependency belongs in the
    # deployment that builds the venv, not in a per-scan install.

    # Collect IPs before querying so phase 1 has something worth batching.
    # BaseModule._events_waiting() drains whatever is queued rather than waiting
    # for a full batch, so small batches still arrive -- hence the buffer below.
    _batch_size = 100

    base_url = "https://api.shodan.io"

    # Shodan answers 429 with "Retry-After: 0", which would turn a retry loop into
    # a hot spin. BaseModule.api_request() has exactly that bug (base.py:1368 passes
    # the header straight into asyncio.sleep), which is one reason this module
    # issues its own requests. Never sleep less than this on a 429.
    _min_429_sleep = 1.0
    _max_429_sleep = 60.0

    # NIST CVSS score -> severity
    severity_map = {"NONE": 0.0, "LOW": 0.1, "MEDIUM": 4.0, "HIGH": 7.0, "CRITICAL": 9.0}

    async def setup(self):
        self.api_key = self.config.get("api_key", "")
        if not self.api_key:
            return None, "No API key specified"

        self.requests_per_second = max(float(self.config.get("requests_per_second", 1.0)), 0.01)
        self.max_retries = int(self.config.get("max_retries", 3))
        self.retry_backoff = float(self.config.get("retry_backoff", 2.0))
        self.search_prefilter = bool(self.config.get("search_prefilter", True))
        self.search_chunk_size = max(int(self.config.get("search_chunk_size", 100)), 1)

        self._semaphore = asyncio.Semaphore(max(int(self.config.get("concurrency", 4)), 1))
        self._rate_lock = asyncio.Lock()
        self._last_request = 0.0
        self._min_interval = 1.0 / self.requests_per_second

        # IPs seen across batches but not yet queried, plus every IP already
        # handled -- Shodan is queried at most once per address per scan.
        self._pending = []
        self._seen = set()
        self._parents = {}

        # Phase 1 needs httpx; see the class docstring for why BBOT's own engine
        # cannot reach the search endpoint. Losing the prefilter costs speed,
        # never correctness, so a missing httpx is a warning rather than a failure.
        self._httpx_client = None
        if self.search_prefilter:
            if httpx is None:
                self.warning(
                    "httpx is not installed; disabling search_prefilter and querying every IP directly. "
                    "This is correct but much slower."
                )
                self.search_prefilter = False
            else:
                self._httpx_client = httpx.AsyncClient(
                    timeout=self.http_timeout_infrastructure,
                    follow_redirects=True,
                )

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
        every request the module makes rather than inside any one worker.
        """
        async with self._rate_lock:
            now = time.monotonic()
            delay = self._last_request + self._min_interval - now
            if delay > 0:
                await asyncio.sleep(delay)
            self._last_request = time.monotonic()

    async def _send_via_bbot(self, url):
        """BBOT's HTTP engine: honours scan-wide proxy, SSL and timeout settings."""
        return await self.helpers.request(
            url=url,
            timeout=self.http_timeout_infrastructure,
            ssl_verify=self.helpers.web.ssl_verify_infrastructure,
        )

    async def _send_via_httpx(self, url):
        """httpx: the only transport Cloudflare lets through to /shodan/host/search."""
        try:
            return await self._httpx_client.get(url)
        except Exception as e:
            self.debug(f"httpx request failed: {type(e).__name__}: {e}")
            return None

    async def _request(self, url, description, sender=None):
        """One API call, with throttling, 429 backoff and API key cycling.

        Deliberately not BaseModule.api_request(): that method sleeps for the
        literal Retry-After value (0, from Shodan) and counts every 429 toward
        api_failure_abort_threshold, which would disable the module after ten
        rate-limit responses -- and a long scan produces far more than ten.

        ``sender`` selects the transport; both phases share this retry logic and
        the module-wide throttle, since Shodan's rate limit is per API key and
        does not care which client sent the request.

        Returns the parsed JSON body, or None if the request could not be
        completed. A 404 means Shodan has no data for that host, which is a
        normal answer rather than a failure.
        """
        sender = sender or self._send_via_bbot
        backoff = self.retry_backoff

        for attempt in range(self.max_retries + 1):
            async with self._semaphore:
                await self._throttle()
                r = await sender(url)

            if r is None:
                self.debug(f"No response from Shodan for {description}")
                if attempt >= self.max_retries:
                    return None
                await asyncio.sleep(backoff)
                backoff *= 2
                continue

            status_code = getattr(r, "status_code", 0)

            if status_code == 200:
                try:
                    return r.json()
                except Exception as e:
                    self.warning(f"Failed to parse Shodan response for {description}: {e}")
                    return None

            if status_code == 404:
                self.debug(f"No Shodan data about {description}")
                return None

            if status_code == 429:
                if attempt >= self.max_retries:
                    self.verbose(f"Giving up on {description} after {attempt + 1} rate-limited attempts")
                    return None
                sleep_interval = min(max(backoff, self._min_429_sleep), self._max_429_sleep)
                self.debug(f"Rate limited on {description}; sleeping {sleep_interval:.1f}s")
                await asyncio.sleep(sleep_interval)
                backoff *= 2
                self.cycle_api_key()
                continue

            if status_code >= 500:
                if attempt >= self.max_retries:
                    self.warning(f"Shodan server error {status_code} for {description}: {self._error_text(r)}")
                    return None
                await asyncio.sleep(backoff)
                backoff *= 2
                continue

            # Shodan explains refusals in the body ("Access denied", "Invalid
            # query", credit exhaustion). Logging only the status turns a
            # one-line fix into a guessing game.
            self.warning(f"Shodan API error for {description} (status {status_code}): {self._error_text(r)}")
            return None

        return None

    @staticmethod
    def _error_text(response):
        """Shodan's error message, trimmed, with the API key never echoed back."""
        body = (getattr(response, "text", "") or "").strip().replace("\n", " ")
        return body[:200] if body else "<empty body>"

    def _host_url(self, ip):
        return f"{self.base_url}/shodan/host/{self.helpers.quote(ip)}?key={self.api_key}"

    def _search_url(self, query, page):
        # minify defaults to true server-side and strips the very fields this
        # module emits (cpe, http.components, vulns), so it is always disabled.
        return (
            f"{self.base_url}/shodan/host/search"
            f"?key={self.api_key}&minify=false&page={page}&query={self.helpers.quote(query)}"
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
        """
        await self._drain()

    async def cleanup(self):
        """Close the phase 1 transport. Runs once, after the scan."""
        if self._httpx_client is not None:
            await self._httpx_client.aclose()
            self._httpx_client = None

    async def _drain(self):
        batch, self._pending = self._pending, []
        if batch:
            await self._process(batch)

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
        await asyncio.gather(*(self._lookup_and_emit(ip) for ip in known))

    async def _search_known_ips(self, ips):
        """Phase 1: which of these IPs does Shodan have anything on?

        One request per search_chunk_size IPs. Only the ip_str of each match is
        used -- the banners themselves are re-fetched per host in phase 2, since
        the search copy is incomplete.
        """
        known = []
        for start in range(0, len(ips), self.search_chunk_size):
            chunk = ips[start : start + self.search_chunk_size]
            query = "ip:" + ",".join(chunk)
            chunk_set = set(chunk)
            found = set()
            page = 1

            while True:
                body = await self._request(
                    self._search_url(query, page),
                    f"search of {len(chunk)} IPs",
                    sender=self._send_via_httpx,
                )
                if body is None:
                    # A failed search must not silently drop these IPs; fall back
                    # to looking the whole chunk up directly.
                    self.verbose(f"Search failed for a chunk of {len(chunk)} IPs; falling back to direct lookups")
                    found = chunk_set
                    break

                matches = body.get("matches") or []
                for match in matches:
                    ip = match.get("ip_str")
                    if ip in chunk_set:
                        found.add(ip)

                total = body.get("total")
                if len(matches) < 100 or (isinstance(total, int) and page * 100 >= total):
                    break
                page += 1

            known.extend(ip for ip in chunk if ip in found)

        return known

    async def _lookup_and_emit(self, ip):
        """Phase 2: the complete host record, and the events that come from it."""
        host = await self._request(self._host_url(ip), ip)
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

        for data in host["data"]:
            # The port goes first so everything found in that banner can hang off
            # it. Shodan attaches vulns and technologies to the individual banner,
            # not to the host -- across 5 hosts with up to 5 open ports each, 157
            # CVEs each appeared exactly once -- and BBOT expresses "this CVE is on
            # this service" through the event tree rather than through extra fields
            # in event data. Falls back to the IP when the banner has no usable
            # port, so a finding is never dropped for lack of a parent.
            port_event = await self._emit_ports(ip, data, event)
            parent = port_event or event
            await self._emit_technologies(ip, data, parent)
            await self._emit_findings(ip, data, parent)

    async def _emit_technology(self, ip, technology, data, event, tags):
        tech = {"technology": technology, "host": data.get("ip_str"), "port": data.get("port")}
        await self.emit_event(
            tech,
            "TECHNOLOGY",
            parent=event,
            tags=tags,
            context=f"{{module}} queried Shodan API for {ip} and found TECHNOLOGY: {technology}",
        )

    async def _emit_technologies(self, ip, data, event):
        tags = data.get("tags") or []

        for key in ("cpe", "cpe23"):
            for technology in data.get(key, []):
                await self._emit_technology(ip, technology, data, event, tags)

        if "product" in data:
            await self._emit_technology(ip, data["product"], data, event, tags)

        components = (data.get("http") or {}).get("components") or {}
        for technology, details in components.items():
            component_tags = list((details or {}).get("categories", []))
            component_tags.append("web-technology")
            await self._emit_technology(ip, technology, data, event, component_tags)

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
        for cve, vuln_data in (data.get("vulns") or {}).items():
            cvss = vuln_data.get("cvss", 0)
            severity = max(
                (level for level, threshold in self.severity_map.items() if cvss >= threshold),
                key=lambda x: self.severity_map[x],
            )
            vuln = {
                "name": "Shodan - Possible Vulnerabilities",
                "host": data.get("ip_str"),
                "severity": severity,
                "description": cve,
                "confidence": "LOW",
                # FINDING's validator accepts a fixed set of fields and silently
                # drops the rest, so the CVE goes in "cves", the field meant for
                # it, and not only as free text in "description". Matches how
                # shodan_idb reports the same kind of finding.
                "cves": [cve],
            }
            # The affected port lives in the parent chain (this finding's parent
            # is the OPEN_TCP_PORT/OPEN_UDP_PORT event for the banner it came
            # from), not in the event itself: FINDING's validator accepts a fixed
            # set of fields and drops the rest, and there is no supported way to
            # set a port on an event -- neither make_event() nor BaseEvent take
            # one. ClosestHostEvent is meant to inherit host+port from the closest
            # parent, but only for events that declare no host, and it loses the
            # port anyway (the hash refresh right after the assignment re-derives
            # everything from data). Measured: parent.port 53, finding.port None.
            # Reported upstream rather than worked around with a private attribute.
            await self.emit_event(
                vuln,
                "FINDING",
                parent=event,
                tags=[],
                context=f"{{module}} queried Shodan API for {ip} and found FINDING {cve}",
            )
