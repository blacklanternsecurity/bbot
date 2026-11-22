from dataclasses import dataclass

from bbot.errors import HttpCompareError
from bbot.core.helpers.web.response_event import extract_title

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
    # the same mutation on two more made-up paths, for a second look at a probe the first two answered differently from
    sibling_urls_again: tuple[str, str] | None = None


def is_allowed_status(status_code):
    """A bypass means we reached the resource: a 2xx. 3xx (usually to auth) and 5xx are not bypasses."""
    return 200 <= int(status_code) < 300


def has_content(response, reasons):
    """A bypass has to show us something: a body, and not the one the block answered with."""
    return "body" in reasons and bool((response.text or "").strip())


def summarize(response):
    """Status, size and title, for showing a response in a finding."""
    summary = f"{response.status_code}, {len(response.content)} bytes"
    title = " ".join(extract_title(response.text).split())
    if title:
        summary += f", '{title[:50]}'"
    return summary


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
        # whether the URL itself no longer answers as it did at baseline: see block_changed()
        self._block_changed = None

    def applies(self):
        return self.event.http_status in self.trigger_status_codes

    def probes(self):
        return []

    async def confirm(self, probe, response):
        """Submodule-specific acceptance check, run after the common success rules."""
        return True

    async def describe(self, label, reasons, response):
        """The signature, and the blocked response next to the one that got through."""
        baseline = await self.compare_helper.get_baseline()
        return (
            f"{self.friendly_name}. Signature: [{label}] Baseline: [{summarize(baseline)}] -> "
            f"Probe: [{summarize(response)}] Differences: [{','.join(reasons)}]"
        )

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
            if await self.is_bypass(probe, match, reasons, response):
                self.add_result(await self.describe(probe.label, reasons, response))

    async def get_probes(self):
        return list(self.probes())

    async def is_bypass(self, probe, match, reasons, response):
        if match is not False or response is None:
            return False
        if not is_allowed_status(response.status_code):
            self.access_bypass.debug(f"Status code is {response.status_code} (not 2xx), not a bypass")
            return False
        if not has_content(response, reasons):
            self.access_bypass.debug(f"Rejecting {probe.label}: the {response.status_code} brought no new content")
            return False
        if await self.access_bypass.is_waf_response(response):
            self.access_bypass.debug(f"Rejecting {probe.label} based on presence of WAF string")
            return False
        if probe.sibling_url and await self.is_catch_all(probe):
            self.access_bypass.debug(
                f"Rejecting {probe.label}: the same mutation succeeds on a nonexistent path, or can't be compared"
            )
            return False
        if await self.block_changed():
            self.access_bypass.debug(f"Rejecting {probe.label}: {self.event.url} no longer answers as it did")
            return False
        return await self.confirm(probe, response)

    async def block_changed(self):
        """
        Whether the URL itself no longer answers as it did: its baseline isn't the status it was found blocked with,
        or now it doesn't answer with its baseline's status, or can't be asked. A block that lifts or changes, like a
        rate limit or a bot check giving way, wasn't the site's own answer, and would make every probe after it look
        like a bypass. Asked once, when a probe first gets through.
        """
        if self._block_changed is None:
            baseline = await self.compare_helper.get_baseline()
            if baseline.status_code != self.event.http_status:
                self._block_changed = True
            else:
                response = await self.helpers.request(self.event.url, follow_redirects=self.follow_redirects)
                self._block_changed = response is None or response.status_code != baseline.status_code
        return self._block_changed

    async def is_catch_all(self, probe):
        """Whether the mutation may reach nothing special: a nonexistent sibling path gets the same treatment.

        Baselines against the mutation applied to two random paths, so HttpCompare filters out
        reflected paths, timestamps and other volatile content before deciding whether the real
        target's response matches the junk template. If the two random paths aren't answered alike,
        there's nothing to tell a bypass from, so it may.

        A probe answered differently is compared again with two more random paths: a page that changed between requests,
        like one caught mid-deploy, differs once, while a bypass differs every time.
        """
        if not probe.sibling_url_2:
            return False
        pairs = [(probe.sibling_url, probe.sibling_url_2)]
        if probe.sibling_urls_again:
            pairs.append(probe.sibling_urls_again)
        for url, url_2 in pairs:
            try:
                control = self.helpers.http_compare(
                    url,
                    baseline_url_2=url_2,
                    method=probe.method,
                    headers=probe.headers,
                    allow_redirects=self.follow_redirects,
                    include_cache_buster=False,
                )
                match, _, _, _ = await control.compare(probe.url, headers=probe.headers, method=probe.method)
            except HttpCompareError:
                # the two junk samples disagreed, so a bypass can't be told from a catch-all
                return True
            if match is True:
                return True
        return False
