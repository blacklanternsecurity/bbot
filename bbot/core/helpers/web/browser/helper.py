"""
Real browser support: screenshots, rendered DOMs, and a fallback for pages behind a JavaScript
challenge that no HTTP client can pass.

Off unless `web.enable_browser` is set. Nothing at import time touches the browser engine's
packages, so BBOT runs normally on a machine where they were never installed.
"""

import time
import asyncio
import logging
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field

import blasthttp

from bbot.errors import BrowserError
from bbot.core.helpers.validators import clean_url
from .engines.base import VIEWPORT
from .engines.camoufox import CamoufoxEngine

log = logging.getLogger("bbot.core.helpers.web.browser")

# a challenge page reloads itself once it's solved; how long to wait for that
CHALLENGE_TIMEOUT = 30
# some only set their cookies and don't reload; how long to wait before reloading for them
CHALLENGE_RELOAD_AFTER = 5
# the most a single page operation may take, so a hung page can't hold a slot forever
OPERATION_TIMEOUT = 90
# how long to let a loaded page settle (late requests, rendering) before capturing it
SETTLE_TIMEOUT = 3
# how long a screenshot waits for web fonts before it's taken with whatever has loaded
FONT_TIMEOUT = 30
# stop using the browser for the rest of the scan if it dies this often
MAX_CRASHES = 3
CRASH_WINDOW = 600
# how long a browser that may have died gets to open a context before it's treated as dead
HEALTH_CHECK_TIMEOUT = 30
# finished visits held for modules that haven't collected theirs yet
VISIT_CACHE_SIZE = 100
# a page's requests whose bodies are kept, so modules can use them without fetching them again
NETWORK_BODY_TYPES = {"document", "script", "stylesheet", "xhr", "fetch"}
NETWORK_BODY_MAX = 5 * 1024 * 1024


@dataclass
class BrowserVisit:
    """What one page load captured. `response` is the main document, as a blasthttp Response."""

    url: str
    response: blasthttp.Response
    title: str = ""
    dom: str = None
    screenshot: bytes = None
    # every response the page received: {"url", "status", "method", "resource_type", "response"}, where "response"
    # is a blasthttp Response for text resources fetched with GET (see NETWORK_BODY_TYPES), otherwise None
    network: list = field(default_factory=list)
    # where the page tried to send itself (a script or meta refresh), as (method, url); the page was kept instead
    redirect: tuple = None
    # set by the first module to emit `redirect`, so it's emitted once
    redirect_emitted: bool = False


class RedirectHold:
    """
    Keeps a page from navigating itself away (a script or meta refresh), so what's captured is the page that was
    asked for, including anything its scripts built before redirecting. A challenge page is let through, since it
    navigates once solved.
    """

    def __init__(self, helper, page):
        self.helper = helper
        self.page = page
        # the latest main-frame document
        self.document = None
        self.target = None
        self.caught = asyncio.Event()

    async def start(self):
        self.page.on("response", self._on_response)
        await self.page.route("**/*", self._route)

    def _on_response(self, response):
        if response.frame == self.page.main_frame and response.request.is_navigation_request():
            self.document = response

    async def _route(self, route):
        request = route.request
        # the page's own first load, subresources and iframes go through as normal
        if self.document is None or request.frame != self.page.main_frame or not request.is_navigation_request():
            await route.fallback()
            return
        current = await self.helper._to_response(self.document, self.document.url)
        if current.conclusion[0] == "needs_browser":
            await route.fallback()
            return
        if self.target is None:
            self.target = (request.method, request.url)
        self.caught.set()
        await route.abort("aborted")


@dataclass
class Clearance:
    """
    What lets blasthttp through a challenge the browser passed: the origin's cookies and the browser's User-Agent.
    `response` is what the browser itself got for the URL once past the challenge.
    """

    cookies: dict
    user_agent: str
    response: blasthttp.Response


class _Host:
    """One origin's browser context. Its cookies (e.g. a passed challenge) are shared by every visit and fetch."""

    def __init__(self, context):
        self.context = context
        self.active = 0


class _Instance:
    """One running browser. Replaced when it's recycled, goes idle, or crashes."""

    def __init__(self, browser):
        self.browser = browser
        self.hosts = {}
        self.pages_opened = 0
        self.active = 0
        self.alive = True
        self.closing = False


class BrowserHelper:
    """
    A real browser, shared by everything in the scan that needs one. Which browser is up to the engine.

    One browser runs at a time, launched on first use. Each origin gets its own context, so a challenge
    passed once is passed for every later visit and fetch to that origin. The browser is restarted after
    `web.browser_recycle_after` pages, shut down after `web.browser_idle_timeout` seconds unused, and
    relaunched if it crashes.

    Examples:
        >>> visit = await self.helpers.browser.visit("https://evilcorp.com", consumer=self.name)
        >>> response = await self.helpers.browser.fetch("https://evilcorp.com/robots.txt")
        >>> context = await self.helpers.browser.new_context(bypass_csp=True)
    """

    # the browser engine in use; see engines/base.py for what an engine provides
    engine_class = CamoufoxEngine

    # installed by the deps installer only when web.enable_browser is on, never as part of a module's deps
    config_switch = ("web", "enable_browser")
    deps = engine_class.deps

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        web_config = parent_helper.web_config
        self.enabled = web_config.get("enable_browser", False)
        self.max_pages = web_config.get("browser_max_pages", 4)
        self.recycle_after = web_config.get("browser_recycle_after", 500)
        self.idle_timeout = web_config.get("browser_idle_timeout", 120)
        self.page_timeout = web_config.get("http_timeout", 10) * 3
        # like blasthttp, don't verify target certificates unless asked to (self-signed certs, intercepting proxies)
        self.verify_certs = web_config.get("ssl_verify_target", False)
        self._custom_headers = web_config.get("http_headers", {}) or {}
        self._custom_cookies = web_config.get("http_cookies", {}) or {}

        self._page_slots = asyncio.Semaphore(self.max_pages)
        self._launch_lock = asyncio.Lock()
        self.engine = self.engine_class(parent_helper)
        self._instance = None
        self._idle_task = None
        self._last_used = time.monotonic()
        # recent crash times, for deciding when to give up, and a running total, for noticing one happened
        self._crashes = []
        self._crash_count = 0
        self._crashed_out = False
        self._closing_tasks = set()

        self._artifacts = None
        self._consumers = None
        self._visits = {}
        self._inflight = {}

    @property
    def usable(self):
        return self.enabled and not self._crashed_out

    # -- public api --

    async def visit(self, url, consumer=None):
        """
        Load a page and capture what the scan's browser modules asked for (their `browser_artifacts`).

        Each URL is loaded once: a module asking for a URL that's already loading waits for that load, and one
        asking later gets the cached result, until every interested module has collected it. Returns a
        `BrowserVisit`, or None if the page couldn't be loaded.
        """
        self._check_enabled()
        if consumer is not None:
            visit = self._collect(url, consumer)
            if visit is not None:
                return visit
        future = self._inflight.get(url)
        if future is None:
            future = asyncio.get_running_loop().create_future()
            self._inflight[url] = future
            try:
                visit = await self._with_retry(self._visit, url)
                future.set_result(visit)
            except BaseException as e:
                future.set_exception(e)
                raise
            finally:
                self._inflight.pop(url, None)
            self._cache_visit(url, visit)
        else:
            visit = await asyncio.shield(future)
        if consumer is not None:
            self._collect(url, consumer)
        return visit

    async def fetch(self, url):
        """
        Load a URL in the browser and return what it got, as a blasthttp Response, or None on failure. The request
        carries the origin's cookies (e.g. a passed challenge) and the browser's own network fingerprint, and works for
        any response, including one the browser would otherwise download.
        """
        self._check_enabled()
        return await self._with_retry(self._fetch, url)

    async def clearance(self, url):
        """
        Pass whatever challenge guards `url`, and return a `Clearance` that lets blasthttp through it too. Returns None
        if the browser couldn't get past it.
        """
        self._check_enabled()
        return await self._with_retry(self._clearance, url)

    async def new_context(self, **options):
        """
        A fresh Playwright context on the scan's browser, for a module that drives pages itself. `options` are
        Playwright's `new_context()` options.

        Its requests follow the same rules as every other browser request: the scan's blacklist, and its custom
        headers and cookies for in-scope URLs. A route the module adds runs ahead of those rules, so it should end in
        `route.fallback()`, and fetch through `route_fetch()` if it changes a response.

        It holds one of the browser's page slots (`web.browser_max_pages`) until it's closed.
        """
        self._check_enabled()
        await self._page_slots.acquire()
        try:
            for attempt in (1, 2):
                crashes_before = self._crash_count
                try:
                    instance = await self._get_instance()
                    context = await self._new_context(instance, **options)
                    break
                except Exception as e:
                    # a browser that died is relaunched once
                    if attempt == 2 or not await self._died(e, crashes_before):
                        raise
        except BaseException:
            self._page_slots.release()
            raise
        instance.active += 1

        def on_page(_):
            instance.pages_opened += 1

        # also fires if the browser dies, so the slot is never lost
        def on_close(_):
            instance.active -= 1
            self._last_used = time.monotonic()
            self._page_slots.release()
            if instance.closing and instance.active == 0:
                self._retire(instance)

        context.on("page", on_page)
        context.on("close", on_close)
        return context

    async def route_fetch(self, route, headers=None, **options):
        """
        `route.fetch()` under the scan's blacklist and custom headers and cookies, for a module's route handler that
        changes a response. Returns None if the blacklist forbids the request.
        """
        request = route.request
        if self.parent_helper.preset.blacklisted(request.url):
            return None
        headers = headers if headers is not None else request.headers
        headers = self._scan_headers(request.url, headers) or headers
        return await route.fetch(headers=headers, **options)

    async def shutdown(self):
        if self._idle_task is not None:
            self._idle_task.cancel()
            with suppress(BaseException):
                await self._idle_task
            self._idle_task = None
        if self._instance is not None:
            await self._close_instance(self._instance)
            self._instance = None
        await self.engine.stop()

    # -- visits --

    async def _visit(self, url):
        artifacts = self._enabled_artifacts()
        async with self._page(url) as page:
            responses = []
            if "network" in artifacts:
                page.on("response", lambda r: responses.append(r))
            main, redirect = await self._open(page, url)
            if main is None:
                return None
            visit = BrowserVisit(url=url, response=main, title=await page.title(), redirect=redirect)
            # bodies are read while the page is still open
            for response in responses:
                visit.network.append(await self._network_entry(response))
            if "dom" in artifacts:
                visit.dom = await page.content()
            if "screenshot" in artifacts:
                try:
                    await asyncio.wait_for(
                        page.evaluate("document.fonts.ready.then(() => true)"), timeout=FONT_TIMEOUT
                    )
                except asyncio.TimeoutError:
                    # playwright's screenshot waits on the same fonts; stopping the stalled loads settles them
                    log.verbose(
                        f"Web fonts still loading on {url} after {FONT_TIMEOUT}s, taking the screenshot without them"
                    )
                    await page.evaluate("window.stop()")
                visit.screenshot = await page.screenshot()
            return visit

    def _enabled_artifacts(self):
        if self._artifacts is None:
            modules = self.parent_helper.scan.modules.values()
            self._consumers = {m.name for m in modules if m.browser_artifacts}
            self._artifacts = {a for m in modules for a in m.browser_artifacts}
        return self._artifacts

    def _cache_visit(self, url, visit):
        self._enabled_artifacts()
        if visit is None or not self._consumers:
            return
        self._visits[url] = [visit, set(self._consumers)]
        while len(self._visits) > VISIT_CACHE_SIZE:
            self._visits.pop(next(iter(self._visits)))

    def _collect(self, url, consumer):
        entry = self._visits.get(url)
        if entry is None or consumer not in entry[1]:
            return None
        visit, waiting = entry
        waiting.discard(consumer)
        if not waiting:
            self._visits.pop(url, None)
        return visit

    # -- fetches --

    async def _fetch(self, url):
        # its own page rather than a fetch() from another one: no CORS or CSP limits, redirects that cross origins
        # are followed, and a response the browser would download still comes back
        async with self._page(url) as page:
            document, _ = await self._open(page, url)
            return document

    async def _clearance(self, url):
        # load the challenged URL itself, since a challenge may only guard some paths
        async with self._page(url) as page:
            document, _ = await self._open(page, url)
            if document is None or document.conclusion[0] == "needs_browser":
                return None
            cookies = {c["name"]: c["value"] for c in await page.context.cookies([url])}
            user_agent = await page.evaluate("() => navigator.userAgent")
            return Clearance(cookies=cookies, user_agent=user_agent, response=document)

    # -- pages --

    @asynccontextmanager
    async def _page(self, url):
        async with self._page_slots:
            instance, host = await self._host(url)
            page = await self._new_page(instance, host)
            host.active += 1
            instance.active += 1
            try:
                yield page
            finally:
                host.active -= 1
                instance.active -= 1
                self._last_used = time.monotonic()
                await self._close_page(instance, page)
                if instance.closing and instance.active == 0:
                    await self._close_instance(instance)

    async def _new_page(self, instance, host):
        instance.pages_opened += 1
        return await host.context.new_page()

    async def _close_page(self, instance, page):
        try:
            await asyncio.wait_for(page.close(), timeout=10)
        except Exception:
            # a page that won't close means the browser is in a bad state; replace it
            log.verbose("Browser page failed to close; restarting the browser")
            self._retire(instance)

    async def _open(self, page, url):
        """
        Load `url` in `page`, keeping the page there if it tries to redirect itself. Returns the main document (see
        `_load`) and where the page tried to go, if anywhere.
        """
        hold = RedirectHold(self, page)
        await hold.start()
        return await self._load(page, url, hold), hold.target

    async def _load(self, page, url, hold=None):
        """
        Navigate to `url` and wait out any challenge. Returns the main document as a blasthttp Response, judged by
        blasthttp's own challenge detection, or None if the page didn't load. With a `RedirectHold`, the page stays
        put if it tries to redirect itself.
        """
        documents = asyncio.Queue()

        def on_response(response):
            if response.frame == page.main_frame and response.request.is_navigation_request():
                documents.put_nowait(response)

        page.on("response", on_response)
        error = None
        try:
            await self._navigate(page, url, hold)
        except Exception as e:
            error = e
            if documents.empty():
                log.debug(f"Browser failed to load {url}: {e}")
                return None
        main = await self._latest_document(documents, url)
        # a redirect to somewhere that failed leaves the browser showing its own error page, not the site
        if error is not None and 300 <= main.status_code < 400:
            log.debug(f"Browser failed to load {url} after a redirect to {main.headers.get('location')}: {error}")
            return None
        deadline = time.monotonic() + CHALLENGE_TIMEOUT
        reloaded = False
        # a solved challenge navigates to the real page, so keep taking main documents until one isn't a challenge
        while main.conclusion[0] == "needs_browser":
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                log.verbose(f"Browser could not get past the {main.conclusion[1]} challenge at {url}")
                break
            try:
                wait = remaining if reloaded else min(remaining, CHALLENGE_RELOAD_AFTER)
                next_document = await asyncio.wait_for(documents.get(), timeout=wait)
            except asyncio.TimeoutError:
                if not reloaded:
                    reloaded = True
                    with suppress(Exception):
                        await page.reload(wait_until="load", timeout=self.page_timeout * 1000)
                continue
            with suppress(Exception):
                await page.wait_for_load_state("load", timeout=self.page_timeout * 1000)
            documents.put_nowait(next_document)
            main = await self._latest_document(documents, url)
        with suppress(Exception):
            await page.wait_for_load_state("networkidle", timeout=SETTLE_TIMEOUT * 1000)
        self.parent_helper.web.record_conclusion(main, by_browser=True)
        return main

    async def _navigate(self, page, url, hold):
        goto = asyncio.ensure_future(page.goto(url, wait_until="load", timeout=self.page_timeout * 1000))
        if hold is None:
            await goto
            return
        caught = asyncio.ensure_future(hold.caught.wait())
        try:
            await asyncio.wait({goto, caught}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            caught.cancel()
        if goto.done():
            goto.result()
            return
        # a redirect caught before the page finished loading means it never will: its document is already complete
        goto.cancel()
        with suppress(BaseException):
            await goto

    async def _latest_document(self, documents, url):
        response = None
        while not documents.empty():
            response = documents.get_nowait()
        return await self._to_response(response, url)

    async def _network_entry(self, response):
        request = response.request
        entry = {
            "url": response.url,
            "status": response.status,
            "method": request.method,
            "resource_type": request.resource_type,
            "response": None,
        }
        if request.method == "GET" and request.resource_type in NETWORK_BODY_TYPES:
            converted = await self._to_response(response, response.url)
            if len(converted.content) <= NETWORK_BODY_MAX:
                entry["response"] = converted
        return entry

    async def _to_response(self, response, request_url):
        """A browser response as a blasthttp Response."""
        try:
            body = await response.body()
        except Exception:
            # redirects have no body, and the browser may have already discarded one
            body = b""
        headers = [(h["name"], h["value"]) for h in await response.headers_array()]
        peer_ip = None
        with suppress(Exception):
            peer_ip = ((await response.server_addr()) or {}).get("ipAddress")
        return blasthttp.Response(
            response.url,
            response.status,
            headers=headers,
            body=body,
            request_url=request_url,
            peer_ip=peer_ip,
        )

    # -- browser lifecycle --

    async def _host(self, url):
        """The running browser, and the context for this URL's origin, launching either if needed."""
        instance = await self._get_instance()
        # https://host:443 and https://host are one origin, and must share one context's cookies
        parsed = clean_url(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        host = instance.hosts.get(origin)
        if host is None:
            host = _Host(await self._new_context(instance))
            instance.hosts[origin] = host
            await self._evict_hosts(instance, keep=origin)
        else:
            # most recently used last
            instance.hosts[origin] = instance.hosts.pop(origin)
        return instance, host

    async def _new_context(self, instance, **options):
        """A context on `instance`, its requests routed through the scan's blacklist, headers and cookies."""
        options = {
            "ignore_https_errors": not self.verify_certs,
            "viewport": {"width": VIEWPORT[0], "height": VIEWPORT[1]},
            **options,
        }
        context = await instance.browser.new_context(**options)
        await context.route("**/*", self._route)
        return context

    async def _evict_hosts(self, instance, keep):
        # keep at most max_pages origins' contexts open, skipping any in use and the one just opened
        idle = [origin for origin, host in instance.hosts.items() if host.active == 0 and origin != keep]
        for origin in idle[: max(0, len(instance.hosts) - self.max_pages)]:
            host = instance.hosts.pop(origin)
            with suppress(Exception):
                await asyncio.wait_for(host.context.close(), timeout=10)

    async def _route(self, route):
        request = route.request
        if self.parent_helper.preset.blacklisted(request.url):
            await route.abort("blockedbyclient")
            return
        headers = self._scan_headers(request.url, request.headers)
        if headers is not None:
            await route.continue_(headers=headers)
            return
        await route.continue_()

    def _scan_headers(self, url, headers):
        """
        `headers` plus the scan's custom headers and cookies, which are only sent to in-scope URLs (as with
        blasthttp). None if there's nothing to add.
        """
        if not (self._custom_headers or self._custom_cookies) or not self.parent_helper.preset.in_target(url):
            return None
        headers = {k.lower(): v for k, v in headers.items()}
        for k, v in self._custom_headers.items():
            headers.setdefault(k.lower(), str(v))
        if self._custom_cookies:
            cookies = "; ".join(f"{k}={v}" for k, v in self._custom_cookies.items())
            headers["cookie"] = f"{headers['cookie']}; {cookies}" if headers.get("cookie") else cookies
        return headers

    async def _get_instance(self):
        async with self._launch_lock:
            if self._crashed_out:
                raise BrowserError("the browser crashed too many times and is disabled for the rest of the scan")
            instance = self._instance
            if instance is not None and instance.pages_opened >= self.recycle_after:
                log.verbose(f"Restarting the browser after {instance.pages_opened:,} pages")
                self._retire(instance)
                instance = None
            if instance is None or not instance.alive:
                instance = await self._launch()
                self._instance = instance
            self._last_used = time.monotonic()
            return instance

    async def _launch(self):
        try:
            browser = await self.engine.launch()
        except Exception as e:
            if not isinstance(e, self.engine.errors):
                # not the browser failing but Playwright's driver (see _died), so the next launch starts a new one
                await self.engine.stop()
            self._record_crash(f"failed to launch: {e}")
            raise BrowserError(f"Failed to launch the browser: {e}") from e
        instance = _Instance(browser)
        browser.on("disconnected", lambda _: self._on_disconnected(instance))
        if self._idle_task is None:
            self._idle_task = asyncio.create_task(self._idle_loop())
        log.verbose(f"Launched the browser ({self.engine.name})")
        return instance

    def _on_disconnected(self, instance):
        instance.alive = False
        if self._instance is instance:
            self._instance = None
        if not instance.closing:
            self._record_crash("crashed")

    def _record_crash(self, what):
        now = time.monotonic()
        self._crash_count += 1
        self._crashes = [t for t in self._crashes if now - t < CRASH_WINDOW] + [now]
        if len(self._crashes) >= MAX_CRASHES:
            self._crashed_out = True
            log.warning(
                f"The browser {what}, and has failed {len(self._crashes)} times in {CRASH_WINDOW // 60} minutes. "
                "Disabling it for the rest of the scan."
            )
        else:
            log.warning(f"The browser {what}; it will be relaunched when next needed")

    def _retire(self, instance):
        """Stop giving out this browser; it's closed once its open pages finish."""
        instance.closing = True
        if self._instance is instance:
            self._instance = None
        if instance.active == 0:
            task = asyncio.create_task(self._close_instance(instance))
            self._closing_tasks.add(task)
            task.add_done_callback(self._closing_tasks.discard)

    async def _close_instance(self, instance):
        instance.closing = True
        instance.alive = False
        with suppress(Exception):
            await asyncio.wait_for(instance.browser.close(), timeout=30)

    async def _idle_loop(self):
        while True:
            await asyncio.sleep(min(15, self.idle_timeout))
            instance = self._instance
            idle_for = time.monotonic() - self._last_used
            if instance is not None and instance.active == 0 and idle_for >= self.idle_timeout:
                log.verbose(f"Shutting down the browser after {int(idle_for)}s unused")
                async with self._launch_lock:
                    if self._instance is instance and instance.active == 0:
                        self._instance = None
                        await self._close_instance(instance)
                        await self.engine.stop()

    async def _with_retry(self, operation, url):
        """Run a page operation, retrying once on a fresh browser if the browser died during it."""
        for attempt in (1, 2):
            if self._crashed_out:
                return None
            crashes_before = self._crash_count
            try:
                return await asyncio.wait_for(operation(url), timeout=OPERATION_TIMEOUT)
            except asyncio.TimeoutError:
                log.verbose(f"Browser timed out on {url}")
                return None
            except Exception as e:
                browser_died = await self._died(e, crashes_before)
                if not browser_died and not isinstance(e, (*self.engine.errors, BrowserError)):
                    raise
                if browser_died and attempt == 1:
                    log.verbose(f"Browser died while loading {url}; retrying")
                    continue
                log.debug(f"Browser error on {url}: {e}")
                return None

    async def _died(self, error, crashes_before):
        """Whether the browser died during an operation that failed with `error`."""
        if self._crash_count > crashes_before or self._instance is None:
            return True
        if isinstance(error, (*self.engine.errors, BrowserError)):
            return False
        # once Playwright's driver exits, every call fails with a plain Exception and the browser never reports a
        # disconnect, so any other error is checked against a fresh context, which also lets a bug surface as one
        instance = self._instance
        try:
            context = await asyncio.wait_for(instance.browser.new_context(), timeout=HEALTH_CHECK_TIMEOUT)
        except Exception:
            async with self._launch_lock:
                # once, however many operations it failed
                if instance.alive:
                    instance.alive = False
                    if self._instance is instance:
                        self._instance = None
                    self._record_crash("stopped answering")
                    await self.engine.stop()
            return True
        with suppress(Exception):
            await context.close()
        return False

    def _check_enabled(self):
        if not self.enabled:
            raise BrowserError("The browser is disabled. Set `web.enable_browser=true` to use it.")
