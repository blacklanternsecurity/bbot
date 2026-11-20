from urllib.parse import parse_qsl, urlparse, urlunparse

from domino.DOMino import Domino
from domino.lib.errors import DominoError

from bbot.errors import BrowserError
from bbot.modules.base import BROWSER_PAGE_TYPES
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
    produced_events = ["FINDING", "WEB_PARAMETER"]
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
    # events come in batches, so the GET parameters of one page are tested together; each run in a batch takes at most
    # time_budget + STOP_GRACE, well within the batch timeout
    _batch_size = 10

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
        # (host, page code fingerprint, name) of each GET parameter DOMino has tested, whether it found it or was given it
        self.tested_parameters = set()
        # the code fingerprint of each page loaded, by (host, page URL), so a parameter's page isn't loaded again to
        # find it: None for one that isn't a page to analyze
        self.page_fingerprints = {}
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

    def precheck_event(self, event):
        if event.type == "WEB_PARAMETER":
            if event.data.get("type") != "GETPARAM":
                return False, "DOMino only tests GET parameters"
            # a parameter seen in a page's own request knows what its endpoint answered with, and DOMino loads only
            # pages
            content_type = event.data.get("content_type")
            if content_type and content_type.split(";")[0].strip().lower() not in BROWSER_PAGE_TYPES:
                return False, f"its endpoint answers with {content_type}, not a page"
            # paramminer finds a name by how the server's response changes, which says nothing of whether the page's
            # code reads it. One the server echoes into the page may reach that code; the rest are lightfuzz's to test
            if str(event.module) == "paramminer_getparams" and "http-reflection" not in event.tags:
                return False, "paramminer found it in the server's response, which doesn't echo it"
            return True
        return super().precheck_event(event)

    async def handle_batch(self, *events):
        # pages first, whose runs test the parameters they discover, and whose fingerprints the parameters reuse
        for event in events:
            if event.type != "WEB_PARAMETER":
                await self.handle_url(event)
        await self.handle_parameters([event for event in events if event.type == "WEB_PARAMETER"])

    async def handle_parameters(self, events):
        """
        Test GET parameters with only the rules that take a parameter's name, each in the request it was found in,
        with exactly the parameters that came with it: an endpoint can need them, like an authorize endpoint its
        client's. Parameters found in the same request are tested together, in one DOMino run of that request.
        """
        # (host, fingerprint, page, the request's parameters): [event]
        requests = {}
        for event in events:
            name = event.data["name"]
            page = page_url(event.data["url"])
            params = dict(event.data.get("additional_params") or {})
            if event.data.get("original_value") is not None:
                params[name] = event.data["original_value"]
            fingerprint = await self.page_fingerprint(event.host, page, params)
            if fingerprint is None:
                continue
            requests.setdefault((str(event.host), fingerprint, page, tuple(sorted(params.items()))), []).append(event)
        for (host, fingerprint, page, params), found in requests.items():
            url = self.helpers.add_get_params(page, dict(params)).geturl() if params else page
            # once on each host for each page code: pages running the same code read a parameter the same way
            names = []
            for name in sorted({event.data["name"] for event in found}):
                if (host, fingerprint, name) in self.tested_parameters:
                    self.debug(f"Skipping {name} on {url}: DOMino already tested it on a page with the same code")
                else:
                    names.append(name)
            if not names:
                continue
            self.tested_parameters.update((host, fingerprint, name) for name in names)
            try:
                results, _ = await self.run_domino(url, parameters=names)
            except (BrowserError, *self.helpers.browser.engine.errors) as e:
                self.verbose(f"Browser error while testing {', '.join(names)} on {url}: {e}")
                continue
            tested = [event for event in found if event.data["name"] in names]
            for result in results:
                await self.emit_results(self.parameter_tested(result, url, tested), url, [result])

    async def page_fingerprint(self, host, page, params):
        """
        The code fingerprint of `page`, as a page module worked it out, or by loading it with `params`; None if it isn't
        a page.
        """
        key = (str(host), page)
        url = self.helpers.add_get_params(page, params).geturl() if params else page
        if key not in self.page_fingerprints:
            shared = self.helpers.browser.code_fingerprints.get(url) or self.helpers.browser.code_fingerprints.get(
                page
            )
            if shared is not None:
                self.page_fingerprints[key] = shared
        if key not in self.page_fingerprints:
            try:
                code = await self.url_code(url)
            except (BrowserError, *self.helpers.browser.engine.errors) as e:
                self.verbose(f"Browser error while loading {url}: {e}")
                return None
            self.page_fingerprints[key] = code[2] if code is not None else None
        return self.page_fingerprints[key]

    @staticmethod
    def parameter_tested(result, url, events):
        """Of the parameter `events` tested at `url`, the one `result` is about: the one its detection URL changed."""
        detected = dict(parse_qsl(urlparse(result.get("detection_url") or "").query, keep_blank_values=True))
        tested = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        for event in events:
            name = event.data["name"]
            if name in detected and detected[name] != tested.get(name):
                return event
        return events[0]

    async def handle_url(self, event):
        url = event.url
        # DOMino loads the page itself, so it needs only the page's fingerprint, often from a module that loaded it
        fingerprint = await self.fingerprint_of(event)
        if fingerprint is None:
            return
        self.page_fingerprints[(str(event.host), page_url(url))] = fingerprint
        # what DOMino finds depends on the server as well as the code, so pages are only skipped within one host
        try:
            (results, finished), first = await self.analyze_once(
                (str(event.host), fingerprint), lambda: self.run_domino(url)
            )
        except (BrowserError, *self.helpers.browser.engine.errors) as e:
            self.verbose(f"Browser error while scanning {url}: {e}")
            return
        if not first:
            self.debug(f"Skipping {url}: DOMino already ran on a page on {event.host} with the same code")
            return
        discovered = [
            result["value_found"]
            for result in results
            if "GET Parameter Access" in result["rule_name"] and result.get("value_found")
        ]
        await self.emit_results(event, url, results)
        if finished:
            # DOMino tested what it discovered, so a WEB_PARAMETER for one of those isn't tested again
            self.tested_parameters.update((str(event.host), fingerprint, name) for name in discovered)
        elif discovered and self.wants_parameters():
            # it ran out of time before testing what it discovered, so each is handed on to be tested on its own
            await self.emit_page_parameters(event, discovered, "DOMino")

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
                # DOMino says when a finding isn't confirmed, like one where what ran was its own stand-in response
                confidence=result.get("confidence", "confirmed").upper(),
                context=f"{{module}} ran DOMino on {url} and found {{event.type}}: {rule_name}",
            )

    async def run_domino(self, url, parameters=None):
        """
        DOMino's results for `url`, which are the ones it made in time if it ran out, or none if it didn't stop, and
        whether it finished. With `parameters`, it tests only those GET parameters.
        """
        domino = Domino(
            url,
            logger=self.log,
            json_mode=True,
            selected_rules=self.rules,
            rules_preload_data=self.preloaded_rules,
            browser_engine=self.helpers.browser.engine.name,
            time_budget=self.time_budget,
            # the browser's pages, less one always left for everything else that uses it, shared among the runs DOMino
            # makes at once (module_threads): runs each wanting all of them keep each other waiting
            max_concurrency=max(1, (self.helpers.browser.max_pages - 1) // self.module_threads),
            parameters=parameters,
            parameters_only=bool(parameters),
            # a page answered by a bot challenge instead of the site isn't tested, judged as blasthttp judges responses
            blocked_by=self.helpers.browser.blocked_by,
        )
        try:
            results = (
                await self.helpers.wait_for(domino.run(self.helpers.browser), timeout=self.time_budget + STOP_GRACE)
                or []
            )
        except TimeoutError:
            # an empty result, so pages with the same code are skipped rather than timing out too
            self.warning(f"DOMino didn't stop within {STOP_GRACE}s of its {self.time_budget}s on {url}")
            return [], False
        return results, not domino.ran_out_of_time
