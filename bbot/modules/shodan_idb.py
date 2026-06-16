from bbot.modules.base import BaseModule
import time
from bbot.core.config.models import BaseModuleConfig, Field
from typing import Optional


class shodan_idb(BaseModule):
    """
    Query IP in Shodan InternetDB, returning open ports, discovered technologies, and findings/vulnerabilities

    InternetDB is especially nice because it doesn't require an API key

    API reference: https://internetdb.shodan.io/docs

    Example API response:

    {
        "cpes": [
            "cpe:/a:microsoft:internet_information_services",
            "cpe:/a:microsoft:outlook_web_access:15.0.1367",
        ],
        "hostnames": [
            "autodiscover.evilcorp.com",
            "mail.evilcorp.com",
        ],
        "ip": "1.2.3.4",
        "ports": [
            25,
            80,
            443,
        ],
        "tags": [
            "starttls",
            "self-signed",
            "eol-os"
        ],
        "vulns": [
            "CVE-2021-26857",
            "CVE-2021-26855"
        ]
    }
    """

    watched_events = ["IP_ADDRESS", "DNS_NAME"]
    produced_events = ["TECHNOLOGY", "FINDING", "OPEN_TCP_PORT", "DNS_NAME"]
    flags = ["safe", "passive", "portscan", "subdomain-enum"]
    meta = {
        "description": "Query Shodan's InternetDB for open ports, hostnames, technologies, and vulnerabilities",
        "created_date": "2023-12-22",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        retries: Optional[int] = Field(
            None,
            description="How many times to retry API requests (e.g. after a 429 error). Overrides the global web.api_retries setting.",
        )

    # we typically don't want to abort this module
    _api_failure_abort_threshold = 9999999999

    # since there are rate limits, we set a lower qsize
    # this way when our queue is full, we can give the API a break
    _qsize = 100

    base_url = "https://internetdb.shodan.io"
    cvedb_url = "https://cvedb.shodan.io/cve"

    # CVSS v3 score thresholds per FIRST.org / NVD
    _cvss_severity_thresholds = (
        (9.0, "CRITICAL"),
        (7.0, "HIGH"),
        (4.0, "MEDIUM"),
        (0.1, "LOW"),
    )

    async def setup(self):
        await super().setup()
        self.last_request_time = 0
        self._cve_cache = {}
        return True

    def _incoming_dedup_hash(self, event):
        return hash(self.get_ip(event))

    @property
    def api_retries(self):
        # allow the module to override global retry setting
        return self.config.get("retries", None) or super().api_retries

    async def handle_event(self, event):
        ip = self.get_ip(event)
        if ip is None:
            return
        url = f"{self.base_url}/{ip}"

        # Rate limiting: ensure at least 1 second between requests
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < 1:
            await self.helpers.sleep(1 - time_since_last)

        # Update the last request time
        self.last_request_time = time.time()

        r = await self.api_request(url)
        if r is None:
            self.debug(f"No response for {event.pretty_string}")
            return
        try:
            data = r.json()
        except Exception as e:
            self.verbose(f"Error parsing JSON response from {url}: {e}")
            self.trace()
            return
        if data:
            if r.status_code == 200:
                await self._parse_response(data=data, event=event, ip=ip)
            elif r.status_code == 404:
                detail = data.get("detail", "")
                if detail:
                    self.debug(f"404 response for {url}: {detail}")
            else:
                err_data = data.get("type", "")
                err_msg = data.get("msg", "")
                self.verbose(f"Shodan error for {ip}: {err_data}: {err_msg}")

    async def _parse_response(self, data: dict, event, ip):
        """Handles emitting events from returned JSON"""
        data: dict  # has keys: cpes, hostnames, ip, ports, tags, vulns
        ip = str(ip)
        query_host = ip if event.data == ip else f"{event.pretty_string} ({ip})"
        # ip is a string, ports is a list of ports, the rest is a list of strings
        for hostname in data.get("hostnames", []):
            if hostname != event.data:
                await self.emit_event(
                    hostname,
                    "DNS_NAME",
                    parent=event,
                    context=f'{{module}} queried Shodan\'s InternetDB API for "{query_host}" and found {{event.type}}: {{event.pretty_string}}',
                )
        for cpe in data.get("cpes", []):
            await self.emit_event(
                {"technology": cpe, "host": str(event.host)},
                "TECHNOLOGY",
                parent=event,
                context=f'{{module}} queried Shodan\'s InternetDB API for "{query_host}" and found {{event.type}}: {{event.pretty_string}}',
            )
        for port in data.get("ports", []):
            await self.emit_event(
                self.helpers.make_netloc(event.data, port),
                "OPEN_TCP_PORT",
                parent=event,
                context=f'{{module}} queried Shodan\'s InternetDB API for "{query_host}" and found {{event.type}}: {{event.pretty_string}}',
            )
        vulns = list(dict.fromkeys(data.get("vulns", [])))
        if vulns:
            await self._enrich_cves(vulns)
            cve_entries = []
            for cve_id in vulns:
                details = self._cve_cache.get(cve_id)
                cvss = None
                if details:
                    for key in ("cvss_v3", "cvss", "cvss_v2"):
                        cvss = details.get(key)
                        if cvss is not None:
                            break
                cve_entries.append({"cve": cve_id, "cvss": cvss, "severity": self._cvss_to_severity(cvss)})
            # sort highest CVSS first so the worst shows up first
            cve_entries.sort(key=lambda e: (e["cvss"] is None, -(e["cvss"] or 0), e["cve"]))

            cve_parts = []
            for entry in cve_entries:
                sev = entry["severity"] or "UNKNOWN"
                cvss_str = f"{entry['cvss']}" if entry["cvss"] is not None else "no CVSS"
                cve_parts.append(f"{entry['cve']} [{sev}, {cvss_str}]")
            description = f"Shodan reported possible vulnerabilities for {query_host}: {', '.join(cve_parts)}"

            vulns_str = ", ".join([str(v) for v in vulns])
            await self.emit_event(
                {
                    "description": description,
                    "host": str(event.host),
                    "cves": vulns,
                    "name": "Shodan - Possible Vulnerabilities",
                    # always INFO: shodan_idb only matches banners — there is no exploitation
                    # or in-product confirmation that any of these CVEs are actually present
                    "severity": "INFO",
                    "confidence": "LOW",
                },
                "FINDING",
                parent=event,
                context=f'{{module}} queried Shodan\'s InternetDB API for "{query_host}" and found potential {{event.type}}: {vulns_str}',
            )

    async def _enrich_cves(self, cve_ids):
        """Batch-fetch CVE details from Shodan's CVEDB, skipping any already cached."""
        uncached = [cve_id for cve_id in cve_ids if cve_id not in self._cve_cache]
        if not uncached:
            return
        probes = [(f"{self.cvedb_url}/{cve_id}", {}, cve_id) for cve_id in uncached]
        async for url, response, cve_id in self.helpers.request_batch_stream(probes, threads=10):
            details = None
            if response is not None and response.status_code == 200:
                try:
                    details = response.json()
                except Exception as e:
                    self.verbose(f"Error parsing JSON response from {url}: {e}")
                    self.trace()
            self._cve_cache[cve_id] = details

    @classmethod
    def _cvss_to_severity(cls, score):
        if score is None:
            return None
        try:
            score = float(score)
        except (TypeError, ValueError):
            return None
        for threshold, label in cls._cvss_severity_thresholds:
            if score >= threshold:
                return label
        return None

    def get_ip(self, event):
        """
        Get the first available IP address from an event (IP_ADDRESS or DNS_NAME)
        """
        if event.type == "IP_ADDRESS":
            return event.host
        elif event.type == "DNS_NAME":
            # always try IPv4 first
            ipv6 = []
            ips = [h for h in event.resolved_hosts if self.helpers.is_ip(h)]
            for ip in sorted([str(ip) for ip in ips]):
                if self.helpers.is_ip(ip, version=4):
                    return ip
                elif self.helpers.is_ip(ip, version=6):
                    ipv6.append(ip)
            for ip in ipv6:
                return ip
