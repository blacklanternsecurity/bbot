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
    # the same mutation applied to a random sibling path (catch-all control)
    sibling_url: str | None = None


class BaseAccessBypass:
    """A family of access-bypass probes.

    The default `run()` sends each probe from `probes()` against the event's shared
    HttpCompare and keeps those that turn a blocked response into a non-4xx one.
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
                    probe.url, headers=probe.headers, method=probe.method, allow_redirects=True
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
        if str(response.status_code).startswith("4"):
            self.access_bypass.debug(f"Status code changed to {response.status_code}, ignoring")
            return False
        if await self.access_bypass.is_waf_response(response):
            self.access_bypass.debug(f"Rejecting {probe.label} based on presence of WAF string")
            return False
        if probe.sibling_url and await self.is_catch_all(probe, response):
            self.access_bypass.debug(f"Rejecting {probe.label}: the same mutation succeeds on a nonexistent path")
            return False
        return await self.confirm(probe, response)

    async def is_catch_all(self, probe, response):
        """Whether the mutation produces the same response against a random sibling path."""
        control = await self.helpers.request(
            probe.sibling_url, method=probe.method, headers=probe.headers, follow_redirects=True
        )
        if control is None or str(control.status_code).startswith("4"):
            return False
        if control.status_code != response.status_code:
            return False
        return self.compare_helper.compare_body(
            self.compare_helper.parse_body(response.text or ""), self.compare_helper.parse_body(control.text or "")
        )
