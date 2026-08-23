import math
import ipaddress
from typing import Optional

from bbot.core.config.models import BaseModuleConfig, Field
from bbot.core.helpers.misc import is_ip
from bbot.modules.base import BaseModule


class rustywap(BaseModule):
    """
    Query a RustedWappalyzer API server for web technology detection.

    URLs are submitted in batches to the server's /batch endpoint, which analyzes
    each one and returns detected technologies with versions, CPEs, and (when the
    server has a VulnVault/PocVault/AlertVault MongoDB configured) CVE, PoC, KEV,
    and GHSA advisory data.

    Batching is what keeps this module inside the server's rate limit: the default
    limiter allows 600 requests/minute/IP, and one batch of 100 URLs costs a single
    request, so 10,000 URLs cost 100 requests instead of 10,000.

    Example /batch response (a bare JSON array, one entry per submitted URL):

    [
        {
            "url": "https://evilcorp.com",
            "technologies": [
                {
                    "technology": "Nginx",
                    "confidence": 100,
                    "version": "1.28.0",
                    "cpe": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                    "cves": [
                        {
                            "id": "CVE-2024-7347",
                            "score": 4.7,
                            "severity": "MEDIUM",
                            "description": "...",
                            "published": "2024-08-14"
                        }
                    ],
                    "kev": [],
                    "pocs": [],
                    "advisories": []
                }
            ],
            "error": null
        }
    ]
    """

    watched_events = ["URL"]
    produced_events = ["TECHNOLOGY", "FINDING"]
    # "active" is deliberate: this module only talks to the RustedWappalyzer API, but
    # that API fetches the target itself, so running it generates traffic to the target.
    # Flagging it passive would let it run in passive-only scans and quietly touch hosts.
    flags = ["active", "safe", "web"]
    meta = {
        "description": "Detect web technologies via a RustedWappalyzer API server",
        "created_date": "2026-08-23",
        "author": "@shart123456",
    }

    class Config(BaseModuleConfig):
        api_url: str = Field("http://localhost:3000", description="Base URL of the RustedWappalyzer API")
        api_key: Optional[str] = Field(None, description="Bearer token, if the API server requires one")
        batch_size: int = Field(100, description="URLs submitted per API request (server maximum is 100)")
        concurrency: int = Field(10, description="How many URLs the server analyzes concurrently per batch")
        confidence: int = Field(50, description="Minimum detection confidence (0-100) to emit")
        full_scan: bool = Field(
            False, description="Probe extra endpoints for version info (roughly doubles server-side cost)"
        )
        emit_findings: bool = Field(True, description="Emit FINDINGs for extracted versions and CVEs")
        max_cves_per_tech: int = Field(
            5, description="Maximum CVE FINDINGs to emit per technology, highest CVSS first"
        )

    # matches the server's WappalyzerConfig::max_batch_size — submitting more than
    # this makes the server reject the entire request with a 400
    MAX_API_BATCH = 100
    _batch_size = MAX_API_BATCH
    _module_threads = 2

    # One analysis per host, not per URL and not per host:port.
    #
    # per_hostport_only would treat http://host:80 and https://host:443 as two separate
    # services and analyze both. In practice port 80 almost always redirects to 443, the
    # API follows the redirect, and the result is two identical sets of TECHNOLOGY events
    # at double the API cost. The trade-off is that a genuinely different stack on a
    # second port (an admin app on :8080, say) is only analyzed once per host.
    per_host_only = True

    # the API is usually local; a brief restart shouldn't kill the module, but a
    # genuinely dead server should eventually disable it
    _api_failure_abort_threshold = 20

    # GHSA severity_level uses "MODERATE" where bbot's FINDING schema wants "MEDIUM"
    _ghsa_severity_map = {"MODERATE": "MEDIUM"}

    # CVSS v3 thresholds per FIRST.org, mapped onto bbot's FINDING severity levels
    _cvss_severity_thresholds = (
        (9.0, "CRITICAL"),
        (7.0, "HIGH"),
        (4.0, "MEDIUM"),
        (0.1, "LOW"),
    )

    async def setup(self):
        await super().setup()
        self.api_url = self.config.get("api_url", "http://localhost:3000").rstrip("/")
        self._api_key = self.config.get("api_key", None)
        self.min_confidence = self.config.get("confidence", 50)
        self.full_scan = self.config.get("full_scan", False)
        self.api_concurrency = self.config.get("concurrency", 10)
        self.emit_findings = self.config.get("emit_findings", True)
        self.max_cves_per_tech = self.config.get("max_cves_per_tech", 5)
        self._dropped_urls = 0

        if self.full_scan:
            self.info("full_scan is enabled — expect roughly double the server-side cost per URL")

        # soft-fail (None) rather than hard-fail (False): a missing local API should
        # disable this one module, not abort the operator's entire scan
        health_url = f"{self.api_url}/health"
        r = await self.helpers.request(health_url, headers=self._headers())
        if r is None:
            return None, f"Unable to reach RustedWappalyzer API at {health_url}"
        if r.status_code != 200:
            return None, f"RustedWappalyzer API at {health_url} returned status {r.status_code}"
        return True

    @property
    def batch_size(self):
        # BaseModule lets operators override batch_size via config. The server hard-rejects
        # anything over MAX_API_BATCH, so clamp instead of letting every request 400.
        return min(super().batch_size, self.MAX_API_BATCH)

    @property
    def max_bisect_depth(self):
        """
        How many times a rejected batch may be halved before we give up on it.

        This must be deep enough to reach a *single* URL, or good URLs get discarded
        alongside the offending one: at depth d the chunk size is batch_size / 2**d,
        so a fixed depth of 4 against a 100-URL batch bottoms out at ~6 URLs and
        throws away 6 good results to isolate 1 bad one. ceil(log2(batch_size))
        guarantees we can always narrow down to one.
        """
        return max(1, math.ceil(math.log2(max(self.batch_size, 2))))

    def _headers(self):
        if self._api_key:
            return {"Authorization": f"Bearer {self._api_key}"}
        return {}

    def _is_internal(self, event):
        """
        True if this URL's host is known to be private/loopback.

        The API runs its own SSRF check and rejects the *entire* batch if any single
        URL fails it, so filtering these out locally avoids poisoning good batches.
        This is best-effort — anything we miss is caught by the bisect fallback.
        """
        candidates = [str(event.host)]
        candidates.extend(str(h) for h in (event.resolved_hosts or []))
        for candidate in candidates:
            if not is_ip(candidate):
                continue
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return True
        return False

    async def handle_batch(self, *events):
        url_map = {}
        for event in events:
            if self._is_internal(event):
                self.debug(f"Skipping {event.url} (resolves to private/internal address)")
                self._dropped_urls += 1
                continue
            # last writer wins; per_hostport_only already keeps this near-1:1
            url_map[event.url] = event

        if not url_map:
            self.verbose(f"No submittable URLs in batch of {len(events):,}")
            return

        results = await self._submit(list(url_map))
        for result in results:
            event = url_map.get(result.get("url", ""))
            if event is None:
                # the server normalizes some URLs (e.g. adding a trailing slash),
                # so fall back to matching on the normalized form
                event = self._match_loose(result.get("url", ""), url_map)
            if event is None:
                self.debug(f"Could not correlate API result for {result.get('url', '')!r} back to an event")
                continue
            await self._emit_result(result, event)

    def _match_loose(self, url, url_map):
        stripped = url.rstrip("/")
        for candidate, event in url_map.items():
            if candidate.rstrip("/") == stripped:
                return event
        return None

    async def _submit(self, urls, depth=0):
        """
        POST a list of URLs to /batch, bisecting on a 400.

        The server returns 400 for the *whole* batch if any single URL fails its
        SSRF check, so one bad host would otherwise discard up to 99 good results.
        Halving costs ~7 extra requests to isolate one offender out of 100.
        """
        if not urls:
            return []

        payload = {
            "urls": urls,
            "concurrency": self.api_concurrency,
            "confidence": self.min_confidence,
            "full_scan": self.full_scan,
        }
        r = await self.api_request(
            f"{self.api_url}/batch",
            method="POST",
            json=payload,
            headers=self._headers(),
        )
        if r is None:
            self.verbose(f"No response from API for batch of {len(urls):,} URLs")
            self._dropped_urls += len(urls)
            return []

        if r.status_code == 400:
            return await self._bisect(urls, depth, r)

        if r.status_code != 200:
            self.verbose(f"API returned status {r.status_code} for batch of {len(urls):,} URLs")
            self._dropped_urls += len(urls)
            return []

        try:
            data = r.json()
        except Exception as e:
            self.verbose(f"Error parsing JSON from API batch response: {e}")
            self.trace()
            self._dropped_urls += len(urls)
            return []

        if not isinstance(data, list):
            # the error path returns an object, not an array
            message = data.get("error", data) if isinstance(data, dict) else data
            self.verbose(f"Unexpected API batch response: {message}")
            self._dropped_urls += len(urls)
            return []
        return data

    async def _bisect(self, urls, depth, response):
        reason = ""
        try:
            reason = response.json().get("error", "")
        except Exception:
            reason = getattr(response, "text", "")

        if len(urls) == 1:
            # never silently drop: an unreported discard reads as "nothing detected"
            self.verbose(f"API rejected {urls[0]}: {reason}")
            self._dropped_urls += 1
            return []

        if depth >= self.max_bisect_depth:
            self.warning(
                f"Giving up on {len(urls):,} URLs after {depth} bisect attempts (last error: {reason})",
                trace=False,
            )
            self._dropped_urls += len(urls)
            return []

        self.debug(f"API rejected batch of {len(urls):,} URLs ({reason}); splitting")
        midpoint = len(urls) // 2
        left = await self._submit(urls[:midpoint], depth + 1)
        right = await self._submit(urls[midpoint:], depth + 1)
        return left + right

    async def _emit_result(self, result, event):
        error = result.get("error", None)
        if error:
            self.debug(f"API error for {event.url}: {error}")
            return

        host = str(event.host)
        url = result.get("url", event.url)

        for tech in result.get("technologies", []) or []:
            name = tech.get("technology", "")
            if not name:
                continue

            await self.emit_event(
                {"technology": name.lower(), "url": url, "host": host},
                "TECHNOLOGY",
                parent=event,
                context=f"{{module}} analyzed {url} and identified {{event.type}}: {name.lower()}",
            )

            if not self.emit_findings:
                continue

            version = tech.get("version", None)
            if version:
                # TECHNOLOGY's schema is {host, technology, url} — a "version" key is
                # silently dropped by its pydantic validator, so versions go here instead
                cpe = tech.get("cpe", None)
                description = f"{name} {version}"
                if cpe:
                    description += f" ({cpe})"
                await self.emit_event(
                    {
                        "host": host,
                        "url": url,
                        "severity": "INFO",
                        "name": f"Software Version - {name}",
                        "description": f"Version detected: {description}",
                        "confidence": self._finding_confidence(tech.get("confidence", 0)),
                    },
                    "FINDING",
                    parent=event,
                    context=f"{{module}} analyzed {url} and identified {{event.type}}: {description}",
                )

            emitted_cves = await self._emit_cve_findings(tech, event, url, host, name)
            await self._emit_advisory_findings(tech, event, url, host, name, emitted_cves)

    async def _emit_cve_findings(self, tech, event, url, host, name):
        """Emit one FINDING per CVE, capped at max_cves_per_tech. Returns the CVE ids emitted."""
        cves = tech.get("cves", []) or []
        if not cves:
            return set()

        kev_ids = {k.get("cve_id", "") for k in (tech.get("kev", []) or [])}
        pocs_by_cve = {}
        for poc in tech.get("pocs", []) or []:
            pocs_by_cve.setdefault(poc.get("cve_id", ""), []).append(poc)

        # highest CVSS first, so the cap keeps the worst rather than an arbitrary slice
        ranked = sorted(cves, key=lambda c: c.get("score", 0) or 0, reverse=True)
        emitted = ranked[: self.max_cves_per_tech]
        if len(ranked) > len(emitted):
            self.verbose(
                f"{name} on {url}: emitting top {len(emitted)} of {len(ranked)} CVEs "
                f"(max_cves_per_tech={self.max_cves_per_tech})"
            )

        version = tech.get("version", None)
        tech_label = f"{name} {version}" if version else name
        emitted_ids = set()

        for cve in emitted:
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            emitted_ids.add(cve_id)
            score = cve.get("score", 0) or 0
            severity = self._severity_from_score(score, cve.get("severity", ""))

            description = f"{tech_label} is affected by {cve_id} (CVSS {score})"
            summary = (cve.get("description", "") or "").strip()
            if summary:
                description += f": {summary[:300]}"
            if cve_id in kev_ids:
                description += " [CISA KEV - known exploited]"
            pocs = pocs_by_cve.get(cve_id, [])
            if pocs:
                poc_urls = ", ".join(p.get("url", "") for p in pocs[:3] if p.get("url", ""))
                if poc_urls:
                    description += f" [PoC: {poc_urls}]"

            await self.emit_event(
                {
                    "host": host,
                    "url": url,
                    "severity": severity,
                    "name": f"Vulnerable Software - {tech_label}",
                    "description": description,
                    "confidence": "MEDIUM" if not version else "HIGH",
                    "cves": [cve_id],
                },
                "FINDING",
                parent=event,
                context=f"{{module}} analyzed {url} and identified {severity.lower()} {{event.type}}: {cve_id} in {tech_label}",
            )

        return emitted_ids

    async def _emit_advisory_findings(self, tech, event, url, host, name, emitted_cves):
        """
        Emit FINDINGs for GHSA advisories the CVE pass didn't already cover.

        The API supplements CVE lookups with package-level GitHub advisories, so an
        advisory may carry no CVE at all — those would be lost entirely if we only
        walked the `cves` list. Advisories whose cve_id was already emitted above are
        skipped so the same vulnerability isn't reported twice.
        """
        advisories = tech.get("advisories", []) or []
        if not advisories:
            return

        # an advisory with no CVE is always fresh; one whose CVE we already emitted is not
        fresh = [a for a in advisories if not (a.get("cve_id") and a.get("cve_id") in emitted_cves)]
        if not fresh:
            return

        ranked = sorted(fresh, key=lambda a: a.get("severity", 0) or 0, reverse=True)
        selected = ranked[: self.max_cves_per_tech]
        if len(ranked) > len(selected):
            self.verbose(
                f"{name} on {url}: emitting top {len(selected)} of {len(ranked)} GHSA advisories "
                f"(max_cves_per_tech={self.max_cves_per_tech})"
            )

        version = tech.get("version", None)
        tech_label = f"{name} {version}" if version else name

        for advisory in selected:
            ghsa_id = advisory.get("id", "")
            if not ghsa_id:
                continue
            score = advisory.get("severity", 0) or 0
            level = str(advisory.get("severity_level", "") or "").strip().upper()
            level = self._ghsa_severity_map.get(level, level)
            severity = self._severity_from_score(score, level)

            package = advisory.get("package_name", "")
            ecosystem = advisory.get("ecosystem", "")
            pkg_label = f"{ecosystem}:{package}" if ecosystem and package else (package or ecosystem)

            description = f"{tech_label} is affected by {ghsa_id}"
            if pkg_label:
                description += f" ({pkg_label})"
            summary = (advisory.get("summary", "") or "").strip()
            if summary:
                description += f": {summary[:300]}"

            data = {
                "host": host,
                "url": url,
                "severity": severity,
                "name": f"Vulnerable Package - {tech_label}",
                "description": description,
                "confidence": "MEDIUM" if not version else "HIGH",
            }
            # GHSA ids are not CVE ids, so only populate `cves` when a real CVE is mapped
            cve_id = advisory.get("cve_id", None)
            if cve_id:
                data["cves"] = [cve_id]

            await self.emit_event(
                data,
                "FINDING",
                parent=event,
                context=f"{{module}} analyzed {url} and identified {severity.lower()} {{event.type}}: {ghsa_id} in {tech_label}",
            )

    def _severity_from_score(self, score, reported):
        reported = str(reported).strip().upper()
        if reported in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            return reported
        for threshold, severity in self._cvss_severity_thresholds:
            if score >= threshold:
                return severity
        return "INFO"

    def _finding_confidence(self, confidence):
        # the API reports 0-100; FINDING wants one of bbot's confidence labels
        try:
            confidence = int(confidence)
        except (TypeError, ValueError):
            return "UNKNOWN"
        if confidence >= 100:
            return "CONFIRMED"
        if confidence >= 75:
            return "HIGH"
        if confidence >= 50:
            return "MEDIUM"
        return "LOW"

    async def finish(self):
        if self._dropped_urls:
            self.info(f"{self._dropped_urls:,} URLs were not analyzed (internal address, API error, or rejection)")
