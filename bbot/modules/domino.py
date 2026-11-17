from urllib.parse import urlparse, urlunparse

from domino.DOMino import Domino
from domino.lib.errors import DominoError

from bbot.errors import BrowserError
from bbot.modules.templates.browser_vulns import browser_vulns
from bbot.core.config.models import BaseModuleConfig, Field

# how long DOMino gets past its time budget to close its pages, before it's cut off with nothing
STOP_GRACE = 30


def page_url(url):
    """`url` without its query or fragment: the page a GET parameter belongs to"""
    return urlunparse(urlparse(url)._replace(query="", fragment=""))


class domino(browser_vulns):
    # WEB_PARAMETER only with the web_parameters option: see get_watched_events()
    watched_events = ["URL", "WEB_PARAMETER"]
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
        time_budget: int = Field(
            300, description="Seconds DOMino may spend on one URL, after which it stops and reports what it found"
        )
        web_parameters: bool = Field(
            False,
            description="Also test the GET parameters other modules find, like form fields and the ones paramminer "
            "brute-forces. Turns on excavate's parameter extraction.",
        )

    async def setup(self):
        await super().setup()
        self.rules = self.config.get("rules")
        self.suppress_parameter_discovery_reports = self.config.get("suppress_parameter_discovery_reports", True)
        self.time_budget = self.config.get("time_budget", 300)
        # (page, name) of each GET parameter DOMino has tested, whether it found it or was given it
        self.tested_parameters = set()
        # load the rules once, which also checks the configured ones exist
        try:
            self.preloaded_rules = Domino("", logger=self.log, selected_rules=self.rules).preloaded_rules
        except DominoError as e:
            return False, str(e)
        return True

    def get_watched_events(self):
        # watching WEB_PARAMETER is what turns on excavate's parameter extraction, so it's only watched when wanted
        if self._watched_events is None:
            self._watched_events = set(self.watched_events)
            if not self.config.get("web_parameters", False):
                self._watched_events.discard("WEB_PARAMETER")
        return self._watched_events

    def _incoming_dedup_hash(self, event):
        # a parameter is tested once on each page, however many pages link or submit to it
        if event.type == "WEB_PARAMETER":
            parameter = (page_url(event.data["url"]), event.data["name"])
            return hash(parameter), f"parameter={parameter}"
        return super()._incoming_dedup_hash(event)

    async def filter_event(self, event):
        if event.type == "WEB_PARAMETER":
            if event.data.get("type") != "GETPARAM":
                return False, "DOMino only tests GET parameters"
            return True
        return await super().filter_event(event)

    async def handle_event(self, event):
        if event.type == "WEB_PARAMETER":
            await self.handle_parameter(event)
        else:
            await self.handle_url(event)

    async def handle_parameter(self, event):
        """Test one GET parameter on its page, with only the rules that take a parameter's name"""
        url = event.data["url"]
        name = event.data["name"]
        parameter = (page_url(url), name)
        if parameter in self.tested_parameters:
            self.debug(f"Skipping {name} on {url}: DOMino already tested it there")
            return
        self.tested_parameters.add(parameter)
        try:
            results = await self.run_domino(url, parameters=[name])
        except (BrowserError, *self.helpers.browser.engine.errors) as e:
            self.verbose(f"Browser error while testing {name} on {url}: {e}")
            return
        await self.emit_results(event, url, results)

    async def handle_url(self, event):
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
            if "GET Parameter Access" in result["rule_name"] and result.get("value_found"):
                self.tested_parameters.add((page_url(url), result["value_found"]))
        await self.emit_results(event, url, results)

    async def emit_results(self, event, url, results):
        for result in results:
            rule_name = result["rule_name"]
            if self.suppress_parameter_discovery_reports and "GET Parameter Access" in rule_name:
                continue
            details = result.get("details", [])
            details_string = f" Details: [{','.join(details)}]" if details else ""
            interactions = result.get("interactions", [])
            interactions_string = f" Interactions: [{','.join(interactions)}]" if interactions else ""
            detection_url = result.get("detection_url") or url
            description = (
                f"{result['description']}.{details_string} Detection URL: [{detection_url}]{interactions_string}"
            )
            await self.emit_finding(
                event,
                url=detection_url,
                name=rule_name,
                # one line, whatever the page put into DOMino's details or interactions
                description=" ".join(description.split()),
                severity=result.get("severity", "medium").upper(),
                confidence="CONFIRMED",
                context=f"{{module}} ran DOMino on {url} and found {{event.type}}: {rule_name}",
            )

    async def run_domino(self, url, parameters=None):
        """
        DOMino's results for `url`, which are the ones it made in time if it ran out, or none if it didn't stop. With
        `parameters`, it tests only those GET parameters.
        """
        domino = Domino(
            url,
            logger=self.log,
            json_mode=True,
            selected_rules=self.rules,
            rules_preload_data=self.preloaded_rules,
            browser_engine=self.helpers.browser.engine.name,
            time_budget=self.time_budget,
            # one of the browser's pages always left for everything else that uses it
            max_concurrency=max(1, self.helpers.browser.max_pages - 1),
            parameters=parameters,
            parameters_only=bool(parameters),
        )
        try:
            results = (
                await self.helpers.wait_for(domino.run(self.helpers.browser), timeout=self.time_budget + STOP_GRACE)
                or []
            )
        except TimeoutError:
            # an empty result, so pages with the same code are skipped rather than timing out too
            self.warning(f"DOMino didn't stop within {STOP_GRACE}s of its {self.time_budget}s on {url}")
            return []
        if domino.ran_out_of_time:
            self.warning(f"DOMino ran out of time after {self.time_budget}s on {url}, with {len(results)} findings")
        return results
