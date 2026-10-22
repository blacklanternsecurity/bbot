from dataclasses import dataclass

from bbot.errors import HttpCompareError

# URLs answering with these codes are treated as access-controlled
BLOCKED_STATUS_CODES = (401, 403, 406, 429)


@dataclass
class Probe:
    # stable identifier, used to rebuild the same mutation against a sibling path
    key: str
    # human-readable signature, shown in the finding
    label: str
    url: str
    method: str = "GET"
    headers: dict | None = None
    # the same mutation applied to two random nonexistent paths; the catch-all
    # control baselines against these, so a host that answers everything the same
    # way (reflected paths, timestamps and all) is filtered out by HttpCompare itself
    sibling_url: str | None = None
    sibling_url_2: str | None = None


def is_allowed_status(status_code):
    """A bypass means we reached the resource: a 2xx. 3xx (usually to auth) and 5xx are not bypasses."""
    return 200 <= int(status_code) < 300


class BaseAccessBypass:
    """A family of access-bypass probes.

    The default `run()` sends each probe from `probes()` against the event's shared
    HttpCompare and keeps those that turn a blocked response into a 2xx one.
    Submodules with their own detection logic override `run()`.
    """

    friendly_name = ""
    trigger_status_codes = BLOCKED_STATUS_CODES
    severity = "MEDIUM"
    confidence = "LOW"
    # a probe that errors this many times aborts the submodule for this URL
    max_errors = 3

    def __init__(self, access_bypass, event, compare_helper):
        self.access_bypass = access_bypass
        self.helpers = access_bypass.helpers
        self.event = event
        self.compare_helper = compare_helper
        # blocked-mode checks never follow redirects (a 302 to /login is not a bypass);
        # the shared helper already carries the right setting for this event
        self.follow_redirects = getattr(compare_helper, "allow_redirects", False)
        self.parsed_url = event.parsed_url
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        self.results = []

    def applies(self):
        return self.event.http_status in self.trigger_status_codes

    def probes(self):
        return []

    async def confirm(self, probe, response):
        """Submodule-specific acceptance check, run after the common success rules."""
        return True

    def describe(self, probe, reasons):
        return f"{self.friendly_name}: [{','.join(reasons)}] Sig: [{probe.label}]"

    def add_result(self, description, severity=None, confidence=None, url=None):
        self.results.append(
            {
                "name": "Access Control Bypass",
                "description": description,
                "severity": severity or self.severity,
                "confidence": confidence or self.confidence,
                "url": url or self.event.url,
            }
        )

    async def run(self):
        error_count = 0
        for probe in await self.get_probes():
            if error_count > self.max_errors:
                self.access_bypass.warning(f"Too many errors for {self.event.url}, aborting {self.friendly_name}")
                return
            try:
                match, reasons, _, response = await self.compare_helper.compare(
                    probe.url, headers=probe.headers, method=probe.method, allow_redirects=self.follow_redirects
                )
            except HttpCompareError as e:
                error_count += 1
                self.access_bypass.debug(e)
                continue
            if await self.is_bypass(probe, match, response):
                self.add_result(self.describe(probe, reasons))

    async def get_probes(self):
        return list(self.probes())

    async def is_bypass(self, probe, match, response):
        if match is not False or response is None:
            return False
        if not is_allowed_status(response.status_code):
            self.access_bypass.debug(f"Status code is {response.status_code} (not 2xx), not a bypass")
            return False
        if await self.access_bypass.is_waf_response(response):
            self.access_bypass.debug(f"Rejecting {probe.label} based on presence of WAF string")
            return False
        if probe.sibling_url and await self.is_catch_all(probe):
            self.access_bypass.debug(f"Rejecting {probe.label}: the same mutation succeeds on a nonexistent path")
            return False
        return await self.confirm(probe, response)

    async def is_catch_all(self, probe):
        """Whether the mutation reaches nothing special: a nonexistent sibling path gets the same treatment.

        Baselines against the mutation applied to two random paths, so HttpCompare filters out
        reflected paths, timestamps and other volatile content before deciding whether the real
        target's response matches the junk template.
        """
        if not probe.sibling_url_2:
            return False
        try:
            control = self.helpers.http_compare(
                probe.sibling_url,
                baseline_url_2=probe.sibling_url_2,
                method=probe.method,
                headers=probe.headers,
                allow_redirects=self.follow_redirects,
                include_cache_buster=False,
            )
            match, _, _, _ = await control.compare(probe.url, headers=probe.headers, method=probe.method)
        except HttpCompareError:
            # the two junk samples disagreed (unstable), so we can't call it a catch-all
            return False
        return match is True
