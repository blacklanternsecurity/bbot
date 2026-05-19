
import asyncio
import ipaddress
import shodan
from bbot.modules.base import BaseModule


class shodan_enterprise2(BaseModule):
    watched_events = ["IP_ADDRESS"]
    produced_events = ["OPEN_TCP_PORT", "TECHNOLOGY", "OPEN_UDP_PORT", "ASN", "VULNERABILITY"]
    flags = ["passive"]
    meta = {
        "created_date": "2026-01-27",
        "author": "@Control-Punk-Delete",
        "description": "Shodan Enterprise API integration module with native BBOT batch support.",
    }
    deps_pip = ["shodan"]
    options = {
        "api_key": None,
        "requests_per_second": 1,
        "max_retries": 3,
        "retry_backoff": 2.0,
    }
    options_desc = {
        "api_key": "Shodan API Key",
        "requests_per_second": "Max API requests per second",
        "max_retries": "Retries on rate-limit errors",
        "retry_backoff": "Initial backoff seconds between retries (doubles each attempt)",
    }
    per_host_only = True
    scope_distance_modifier = 1
    target_only = True

    # --- Native BBOT batching ---
    # BBOT will collect up to 100 events and call handle_batch(*events) automatically
    _batch_size = 100
    _module_threads = 10

    _SEVERITY_MAP = {
        "NONE": 0.0,
        "LOW": 0.1,
        "MEDIUM": 4.0,
        "HIGH": 7.0,
        "CRITICAL": 9.0,
    }

    async def setup(self):
        if not self.config.get("api_key"):
            return None, "No API key specified"

        self.api = shodan.Shodan(self.config["api_key"])

        rps = float(self.config.get("requests_per_second", 1))
        self._min_interval = 1.0 / max(rps, 0.01)
        self._last_request_time = 0.0
        self._rate_lock = asyncio.Lock()

        self.max_retries = int(self.config.get("max_retries", 3))
        self.retry_backoff = float(self.config.get("retry_backoff", 2.0))

        return True

    # ------------------------------------------------------------------
    # BBOT calls this automatically with up to _batch_size events
    # ------------------------------------------------------------------

    async def handle_batch(self, *events):
        # Filter out non-public IPs before hitting the API
        valid = {}
        for event in events:
            try:
                if ipaddress.ip_address(event.data).is_global:
                    valid[event.data] = event
                else:
                    self.debug(f"Skipping non-public IP {event.data}")
            except ValueError:
                self.debug(f"Could not parse IP: {event.data}")

        if not valid:
            return

        results = await self._lookup_with_retry(list(valid.keys()))

        if isinstance(results, Exception):
            self.error(f"Shodan API error: {results}")
            return

        for ip, event in valid.items():
            host = results.get(ip)
            if host is None:
                self.debug(f"No Shodan data for {ip}")
                continue
            await self._emit_host_events(event, host)

    # ------------------------------------------------------------------
    # API call with rate limiting + retry
    # ------------------------------------------------------------------

    async def _lookup_with_retry(self, ips: list):
        loop = asyncio.get_running_loop()
        backoff = self.retry_backoff

        for attempt in range(self.max_retries + 1):
            async with self._rate_lock:
                now  = loop.time()
                wait = self._min_interval - (now - self._last_request_time)
                if wait > 0:
                    await asyncio.sleep(wait)

                try:
                    # Single IP -> pass as string; multiple -> pass as list
                    arg = ips[0] if len(ips) == 1 else ips
                    raw = await loop.run_in_executor(
                        None,
                        lambda: self.api.host(ips=arg, history=False, minify=False),
                    )
                    self._last_request_time = loop.time()

                    if isinstance(raw, dict):
                        raw = [raw]
                    return {h["ip_str"]: h for h in raw}

                except shodan.APIError as e:
                    self._last_request_time = loop.time()
                    err = str(e).lower()
                    if ("rate limit" in err or "too many requests" in err) and attempt < self.max_retries:
                        self.warning(
                            f"Shodan rate limit (attempt {attempt + 1}/{self.max_retries}). "
                            f"Retrying in {backoff:.1f}s..."
                        )
                    else:
                        return e

            if attempt < self.max_retries:
                await asyncio.sleep(backoff)
                backoff *= 2

        return shodan.APIError(f"Rate limit persisted after {self.max_retries} retries")

    # ------------------------------------------------------------------
    # Emit events for a single host result
    # ------------------------------------------------------------------

    async def _emit_host_events(self, event, host):
        # ASN
        try:
            await self.emit_event(
                {
                    "asn":         host["asn"][2:],
                    "name":        host.get("org", ""),
                    "description": host.get("isp", ""),
                    "country":     host.get("country_code", ""),
                },
                "ASN",
                parent=event,
                tags=host.get("tags") or [],
                context=f"Shodan API {event.data} -> ASN",
            )
        except (KeyError, TypeError) as e:
            self.debug(f"ASN extraction failed for {event.data}: {e}")

        for data in host.get("data", []):
            ip_str    = data.get("ip_str")
            port      = data.get("port")
            tags      = data.get("tags") or []
            transport = data.get("transport")

            # TECHNOLOGY: CPE / CPE23
            for technology in data.get("cpe", []):
                await self.emit_event(
                    {"technology": technology, "host": ip_str, "port": port},
                    "TECHNOLOGY", parent=event, tags=tags,
                    context=f"Shodan API {event.data} -> TECHNOLOGY: {technology}",
                )
            for technology in data.get("cpe23", []):
                await self.emit_event(
                    {"technology": technology, "host": ip_str, "port": port},
                    "TECHNOLOGY", parent=event, tags=tags,
                    context=f"Shodan API {event.data} -> TECHNOLOGY: {technology}",
                )

            # TECHNOLOGY: product
            if "product" in data:
                await self.emit_event(
                    {"technology": data["product"], "host": ip_str, "port": port},
                    "TECHNOLOGY", parent=event, tags=tags,
                    context=f"Shodan API {event.data} -> TECHNOLOGY: {data['product']}",
                )

            # TECHNOLOGY: HTTP components
            for technology, meta in data.get("http", {}).get("components", {}).items():
                component_tags = list(meta.get("categories", [])) + ["web-technology"]
                await self.emit_event(
                    {"technology": technology, "host": ip_str, "port": port},
                    "TECHNOLOGY", parent=event, tags=component_tags,
                    context=f"Shodan API {event.data} -> TECHNOLOGY: {technology}",
                )

            # OPEN_TCP_PORT / OPEN_UDP_PORT
            if port and transport:
                netloc     = self.helpers.make_netloc(event.data, port)
                event_type = None
                if transport == "tcp":
                    event_type = "OPEN_TCP_PORT"
                elif transport == "udp":
                    event_type = "OPEN_UDP_PORT"
                else:
                    self.warning(f"Unknown transport '{transport}' for {event.data}:{port}")

                if event_type:
                    await self.emit_event(
                        netloc, event_type, parent=event, tags=tags,
                        context=f"Shodan API {event.data} -> {event_type}: {port}",
                    )

            # VULNERABILITY
            for cve, vuln_data in data.get("vulns", {}).items():
                cvss     = vuln_data.get("cvss") or 0.0
                severity = max(
                    (lvl for lvl, threshold in self._SEVERITY_MAP.items() if cvss >= threshold),
                    key=lambda x: self._SEVERITY_MAP[x],
                )
                await self.emit_event(
                    {"host": ip_str, "severity": severity, "description": cve},
                    "VULNERABILITY", parent=event, tags=[],
                    context=f"Shodan API {event.data} -> VULNERABILITY: {cve}",
                )
