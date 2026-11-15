from domino.DOMino import Domino
from domino.lib.errors import DominoError

from bbot.errors import BrowserError
from bbot.modules.templates.browser_vulns import browser_vulns
from bbot.core.config.models import BaseModuleConfig, Field

# the longest DOMino may spend on one URL, after which it stops and reports what it found
SCAN_TIMEOUT = 120
# how long DOMino gets past SCAN_TIMEOUT to close its pages, before it's cut off with nothing
STOP_GRACE = 30


class domino(browser_vulns):
    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["active", "safe"]
    meta = {
        "description": "Find client-side web vulnerabilities (DOM XSS, prototype pollution, and more) with DOMino",
        "created_date": "2025-04-08",
        "author": "@liquidsec",
    }
    # the page's DOM and the scripts it loaded, to tell which pages run the same code
    browser_artifacts = ["dom", "network"]
    # DOMino drives pages in the scan's browser, through self.helpers.browser.new_context()
    uses_browser = True
    # TEMPORARY: DOMino's shared-browser support is unreleased; pin the d0m1n0 release instead before merging into dev
    deps_pip = ["d0m1n0 @ git+https://github.com/blacklanternsecurity/DOMino@bbot-shared-browser"]
    # one URL at a time: DOMino alone wants more of the browser's pages than there are, and each URL has a time budget
    _module_threads = 1

    class Config(BaseModuleConfig):
        rules: list[str] | None = Field(None, description="Rules to run. All of them by default.")
        suppress_parameter_discovery_reports: bool = Field(
            True, description="Use the GET parameters DOMino discovers to drive other rules, without reporting them"
        )

    async def setup(self):
        await super().setup()
        self.rules = self.config.get("rules")
        self.suppress_parameter_discovery_reports = self.config.get("suppress_parameter_discovery_reports", True)
        # load the rules once, which also checks the configured ones exist
        try:
            self.preloaded_rules = Domino("", logger=self.log, selected_rules=self.rules).preloaded_rules
        except DominoError as e:
            return False, str(e)
        return True

    async def handle_event(self, event):
        url = event.url
        page = await self.page_code(event)
        if page is None:
            return
        fingerprint = page[2]
        # what DOMino finds depends on the server as well as the code, so pages are only skipped within one host
        try:
            results, first = await self.analyze_once((str(event.host), fingerprint), lambda: self.run_domino(url))
        except (BrowserError, *self.helpers.browser.engine.errors) as e:
            self.verbose(f"Browser error while scanning {url}: {e}")
            return
        if not first:
            self.debug(f"Skipping {url}: DOMino already ran on a page on {event.host} with the same code")
            return

        for result in results:
            rule_name = result["rule_name"]
            if self.suppress_parameter_discovery_reports and "GET Parameter Access" in rule_name:
                continue
            details = result.get("details", [])
            details_string = f" Details: [{','.join(details)}]" if details else ""
            interactions = result.get("interactions", [])
            interactions_string = f" Interactions: [{','.join(interactions)}]" if interactions else ""
            detection_url = result.get("detection_url") or url
            await self.emit_finding(
                event,
                url=detection_url,
                name=rule_name,
                description=f"{result['description']}.{details_string} Detection URL: [{detection_url}]{interactions_string}",
                severity=result.get("severity", "medium").upper(),
                confidence="CONFIRMED",
                context=f"{{module}} ran DOMino on {url} and found {{event.type}}: {rule_name}",
            )

    async def run_domino(self, url):
        """DOMino's results for `url`, which are the ones it made in time if it ran out, or none if it didn't stop."""
        domino = Domino(
            url,
            logger=self.log,
            json_mode=True,
            selected_rules=self.rules,
            rules_preload_data=self.preloaded_rules,
            browser_engine=self.helpers.browser.engine.name,
            time_budget=SCAN_TIMEOUT,
        )
        try:
            results = (
                await self.helpers.wait_for(domino.run(self.helpers.browser), timeout=SCAN_TIMEOUT + STOP_GRACE) or []
            )
        except TimeoutError:
            # an empty result, so pages with the same code are skipped rather than timing out too
            self.warning(f"DOMino didn't stop within {STOP_GRACE}s of its {SCAN_TIMEOUT}s on {url}")
            return []
        if domino.ran_out_of_time:
            self.warning(f"DOMino ran out of time after {SCAN_TIMEOUT}s on {url}, with {len(results)} findings")
        return results
