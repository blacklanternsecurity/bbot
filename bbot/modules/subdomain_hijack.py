import re
import json
import httpx

from bbot.modules.base import BaseModule
from bbot.core.helpers.misc import tldextract


class subdomain_hijack(BaseModule):
    flags = ["subdomain-hijack", "subdomain-enum", "cloud-enum", "safe", "active", "web-basic", "web-thorough"]
    watched_events = ["DNS_NAME", "DNS_NAME_UNRESOLVED"]
    produced_events = ["FINDING"]
    meta = {"description": "Detect hijackable subdomains"}
    options = {
        "fingerprints": "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json"
    }
    options_desc = {"fingerprints": "URL or path to fingerprints.json"}
    scope_distance_modifier = 3
    _max_event_handlers = 5

    async def setup(self):
        fingerprints_url = self.config.get("fingerprints")
        fingerprints_file = await self.helpers.wordlist(fingerprints_url)
        with open(fingerprints_file) as f:
            fingerprints = json.load(f)
        self.fingerprints = []
        for f in fingerprints:
            try:
                f = Fingerprint(f)
            except Exception as e:
                self.warning(f"Error instantiating fingerprint: {e}")
                continue
            if not (f.domains and f.vulnerable and f.fingerprint and f.cicd_pass):
                self.debug(f"Skipping fingerprint: {f}")
                continue
            self.debug(f"Processed fingerprint: {f}")
            self.fingerprints.append(f)
        if not self.fingerprints:
            return None, "No valid fingerprints"
        self.debug(f"Successfully processed {len(self.fingerprints):,} fingerprints")
        return True

    async def handle_event(self, event):
        hijackable, reason = await self.check_subdomain(event)
        if hijackable:
            source_hosts = []
            e = event
            while 1:
                host = getattr(e, "host", "")
                if host:
                    if e not in source_hosts:
                        source_hosts.append(e)
                    e = e.get_source()
                else:
                    break

            url = f"https://{event.host}"
            description = f'Hijackable Subdomain "{event.data}": {reason}'
            source_hosts = source_hosts[::-1]
            if source_hosts:
                source_hosts_str = str(source_hosts[0].host)
                for e in source_hosts[1:]:
                    source_hosts_str += f" -[{e.module.name}]-> {e.host}"
                description += f" ({source_hosts_str})"
            await self.emit_event(
                {"host": event.host, "url": url, "description": description}, "FINDING", source=event
            )
        else:
            self.debug(reason)

    async def check_subdomain(self, event):
        for f in self.fingerprints:
            for domain in f.domains:
                self_matches = self.helpers.host_in_host(event.data, domain)
                child_matches = any(self.helpers.host_in_host(domain, h) for h in event.resolved_hosts)
                if event.type == "DNS_NAME_UNRESOLVED":
                    if self_matches and f.nxdomain:
                        return True, "NXDOMAIN"
                else:
                    if self_matches or child_matches:
                        for scheme in ("https", "http"):
                            if self.scan.stopping:
                                return False, "Scan cancelled"
                            # first, try base request
                            url = f"{scheme}://{event.data}"
                            match, reason = await self._verify_fingerprint(f, url, cache_for=60 * 60 * 24)
                            if match:
                                return match, reason
                            # next, try subdomain -[CNAME]-> other_domain
                            url = f"{scheme}://{domain}"
                            headers = {"Host": event.data}
                            match, reason = await self._verify_fingerprint(f, url, headers=headers)
                            if match:
                                return match, reason
        return False, f'Subdomain "{event.data}" not hijackable'

    async def _verify_fingerprint(self, fingerprint, *args, **kwargs):
        kwargs["raise_error"] = True
        kwargs["timeout"] = 10
        kwargs["retries"] = 0
        if fingerprint.http_status is not None:
            kwargs["allow_redirects"] = False
        try:
            r = await self.helpers.request(*args, **kwargs)
            if fingerprint.http_status is not None and r.status_code == fingerprint.http_status:
                return True, f"HTTP status == {fingerprint.http_status}"
            text = getattr(r, "text", "")
            if (
                not fingerprint.nxdomain
                and not fingerprint.http_status
                and fingerprint.fingerprint_regex.findall(text)
            ):
                return True, "Fingerprint match"
        except httpx.RequestError as e:
            if fingerprint.nxdomain and "Name or service not known" in str(e):
                return True, f"NXDOMAIN"
        return False, "No match"


class Fingerprint:
    def __init__(self, fingerprint):
        assert isinstance(fingerprint, dict), "fingerprint must be a dictionary"
        self.engine = fingerprint.get("service")
        self.cnames = fingerprint.get("cname", [])
        self.domains = list(set([tldextract(c).registered_domain for c in self.cnames]))
        self.http_status = fingerprint.get("http_status", None)
        self.nxdomain = fingerprint.get("nxdomain", False)
        self.vulnerable = fingerprint.get("vulnerable", False)
        self.fingerprint = fingerprint.get("fingerprint", "")
        self.cicd_pass = fingerprint.get("cicd_pass", False)
        try:
            self.fingerprint_regex = re.compile(self.fingerprint, re.MULTILINE)
        except re.error:
            self.fingerprint_regex = re.compile(re.escape(self.fingerprint), re.MULTILINE)

    def __str__(self):
        return f"{self.engine}: {self.fingerprint} (cnames: {self.cnames}, vulnerable: {self.vulnerable}, cicd_pass: {self.cicd_pass})"
