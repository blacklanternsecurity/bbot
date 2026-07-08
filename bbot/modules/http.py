import time
from http.cookies import SimpleCookie
from urllib.parse import urlparse

import blasthttp

from bbot.core.helpers.web.web import iter_batch_results
from bbot.core.helpers.web.response_event import response_to_event_dict
from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class http(BaseModule):
    watched_events = ["OPEN_TCP_PORT", "URL_UNVERIFIED", "URL"]
    produced_events = ["URL", "HTTP_RESPONSE"]
    flags = ["active", "safe", "web", "social-enum", "subdomain-enum", "cloud-enum"]
    meta = {
        "description": "Visit webpages using blasthttp (native Rust HTTP engine)",
        "created_date": "2026-03-08",
        "author": "@liquidsec",
    }

    class Config(BaseModuleConfig):
        threads: int = Field(50, description="Number of concurrent requests")
        in_scope_only: bool = Field(True, description="Only visit web resources that are in scope.")
        max_response_size: int = Field(5242880, description="Max response size in bytes")
        store_responses: bool = Field(False, description="Save raw HTTP responses to scan folder")

    scope_distance_modifier = 2
    _shuffle_incoming_queue = False
    _batch_size = 250
    _priority = 2
    # accept Javascript URLs
    accept_url_special = True

    async def setup(self):
        self.threads = self.config.get("threads", 50)
        self.max_response_size = self.config.get("max_response_size", 5242880)
        self.store_responses = self.config.get("store_responses", False)
        self.client = self.helpers.blasthttp
        self.waf_yara_rule = self.helpers.yara.compile_strings(self.helpers.get_waf_strings(), nocase=True)
        self._host_cooldowns = {}
        self._deferred_events = []
        self._429_retry_counts = {}
        self._max_429_retries = 3
        self._429_default_interval = self.scan.web_config.get("429_sleep_interval", 30)
        self._429_max_interval = self.scan.web_config.get("429_max_sleep_interval", 60)
        self._wakeup_target = 0
        return True

    async def filter_event(self, event):
        if "_wildcard" in str(event.host).split("."):
            return False, "event is wildcard"

        if "unresolved" in event.tags:
            return False, "event is unresolved"

        if event.module == self:
            return False, "event is from self"

        if "spider-max" in event.tags:
            return False, "event exceeds spidering limits"

        # scope filtering
        in_scope_only = self.config.get("in_scope_only", True)
        if "blasthttp-safe" in event.tags:
            return True
        max_scope_distance = 0 if in_scope_only else (self.scan.scope_search_distance + 1)
        if event.scope_distance > max_scope_distance:
            return False, "event is not in scope"
        return True

    def make_url_metadata(self, event):
        """Returns (urls, url_hash) where urls is a list (usually 1 item, but 2 for OPEN_TCP_PORT)."""
        has_spider_max = "spider-max" in event.tags
        url_hash = None
        if event.type.startswith("URL"):
            # we NEED the port, otherwise it will try HTTPS even for HTTP URLs
            url = event.with_port().geturl()
            if event.parsed_url.path == "/":
                url_hash = hash((event.host, event.port, has_spider_max))
            urls = [url]
        else:
            # OPEN_TCP_PORT — probe both http and https (but skip mismatched well-known ports)
            host = event.host
            port = event.port
            netloc = self.helpers.make_netloc(host, port)
            if port == 443:
                urls = [f"https://{netloc}/"]
            elif port == 80:
                urls = [f"http://{netloc}/"]
            else:
                urls = [f"http://{netloc}/", f"https://{netloc}/"]
            url_hash = hash((host, port, has_spider_max))
        if url_hash is None:
            url_hash = hash((urls[0], has_spider_max))
        return urls, url_hash

    def _incoming_dedup_hash(self, event):
        urls, url_hash = self.make_url_metadata(event)
        return url_hash

    @property
    def finished(self):
        if self._deferred_events:
            return False
        return super().finished

    def is_incoming_duplicate(self, event, add=False):
        if getattr(event, "_429_retry", False):
            event._429_retry = False
            return False, "429 retry"
        return super().is_incoming_duplicate(event, add=add)

    def _host_is_cooled_down(self, host):
        return time.monotonic() < self._host_cooldowns.get(host, 0)

    def _set_host_cooldown(self, host, seconds):
        resume_time = time.monotonic() + seconds
        self._host_cooldowns[host] = max(self._host_cooldowns.get(host, 0), resume_time)

    def _parse_retry_after(self, response):
        for k, v in response.headers.items():
            if k.lower() == "retry-after":
                try:
                    seconds = max(1, int(v))
                    return min(seconds, self._429_max_interval)
                except ValueError:
                    pass
                break
        return self._429_default_interval

    def _defer_event(self, event):
        if event not in self._deferred_events:
            self._deferred_events.append(event)
            return True
        return False

    async def _flush_deferred(self):
        if not self._deferred_events or self.incoming_event_queue is False:
            return
        still_deferred = []
        flushed = 0
        earliest_resume = None
        now = time.monotonic()
        for event in self._deferred_events:
            host = str(event.host)
            resume_time = self._host_cooldowns.get(host, 0)
            if now >= resume_time:
                event._429_retry = True
                self.incoming_event_queue.put_nowait(event)
                flushed += 1
            else:
                still_deferred.append(event)
                if earliest_resume is None or resume_time < earliest_resume:
                    earliest_resume = resume_time
        self._deferred_events = still_deferred
        # prune expired cooldowns
        self._host_cooldowns = {h: t for h, t in self._host_cooldowns.items() if t > now}
        if flushed:
            async with self.event_received:
                self.event_received.notify()
        if still_deferred and earliest_resume is not None:
            if not self._wakeup_target or earliest_resume < self._wakeup_target:
                delay = max(0.1, earliest_resume - time.monotonic())
                self._wakeup_target = earliest_resume
                self.helpers.create_task(self._deferred_wakeup(delay))

    async def _deferred_wakeup(self, delay):
        await self.helpers.sleep(delay)
        self._wakeup_target = 0
        await self._flush_deferred()

    def _build_headers(self):
        """Build list of (name, value) header tuples from scan config."""
        headers = [("User-Agent", self.scan.useragent)]
        for hk, hv in self.scan.custom_http_headers.items():
            headers.append((hk, hv))
        if self.scan.custom_http_cookies:
            cookie = SimpleCookie()
            for ck, cv in self.scan.custom_http_cookies.items():
                cookie[ck] = cv
            cookie_value = cookie.output(header="", sep="; ").strip()
            headers.append(("Cookie", cookie_value))
        return headers

    def _response_to_json(self, url_input, response):
        """Convert a blasthttp Response to a dict for HTTP_RESPONSE events."""
        return response_to_event_dict(response, url_input, method="GET")

    async def _process_result(self, result, parent_event):
        """Emit URL + HTTP_RESPONSE events for one batch result. Returns True if status was usable."""
        if not result.success:
            error_str = str(result.error)
            retries = self.scan.http_retries
            if "timeout" in error_str.lower():
                self.verbose(f"HTTP timeout for {result.url} (after {retries + 1} attempt(s))")
            else:
                self.debug(f"HTTP error for {result.url}: {error_str}")
            return False

        response = result.response
        status_code = response.status
        if status_code == 0:
            self.debug(f'No HTTP status code for "{result.url}"')
            return False

        url = response.url

        # The "input" field represents the original scan target (host:port),
        # not the full URL. Other modules and output consumers use this to
        # correlate responses back to the target that produced them.
        input_parsed = urlparse(result.url)
        url_input = input_parsed.netloc or result.url
        j = self._response_to_json(url_input, response)

        # discard 404s from unverified URLs
        path = j.get("path", "/")
        if parent_event.type == "URL_UNVERIFIED" and status_code in (404,) and path != "/":
            self.debug(f'Discarding 404 from "{url}"')
            return True

        # discard 4xx responses that contain WAF strings
        if 400 <= status_code < 500:
            body = j.get("body", "")
            if body and await self.helpers.yara.match(self.waf_yara_rule, body):
                self.debug(f'Discarding WAF {status_code} from "{url}"')
                return True

        tags = [f"status-{status_code}"]
        url_context = "{module} visited {event.parent.data} and got status code {event.http_status}"
        if parent_event.type == "OPEN_TCP_PORT":
            url_context += " at {event.data}"

        url_event = self.make_event(url, "URL", parent_event, tags=tags, context=url_context)
        if url_event:
            response_ip = j.get("host", "")
            if response_ip:
                url_event.resolved_hosts = (response_ip,)
            title = j.get("title", "")
            if title:
                url_event.http_title = title
            location = j.get("location", "")
            if location:
                url_event.redirect_location = location
            response_hash = j.get("hash")
            if response_hash:
                url_event.data["hash"] = response_hash
            if url_event != parent_event:
                await self.emit_event(url_event)
            content_type = j.get("header", {}).get("content_type", "unspecified").split(";")[0]
            content_length = self.helpers.bytes_to_human(j.get("content_length", 0))
            await self.emit_event(
                j,
                "HTTP_RESPONSE",
                url_event,
                tags=url_event.tags,
                context=f"HTTP_RESPONSE was {content_length} with {content_type} content type",
            )

        if self.store_responses:
            response_dir = self.scan.home / "http_responses"
            self.helpers.mkdir(response_dir)
            filename = f"{j['host']}.{urlparse(url).port or 443}{path.replace('/', '[slash]')}.txt"
            response_file = response_dir / filename
            response_file.write_text(j.get("raw_header", "") + j.get("body", ""))
        return True

    async def handle_batch(self, *events):
        stdin = {}
        # Track dual-scheme probes from OPEN_TCP_PORT: {(host, port): {"http": url, "https": url}}
        port_probes = {}
        # Reverse index: each paired probe URL → its (host, port) key
        paired_probe_urls = {}

        for event in events:
            urls, url_hash = self.make_url_metadata(event)
            host = str(event.host)
            if self._host_is_cooled_down(host):
                self._defer_event(event)
                continue
            for url in urls:
                stdin[url] = event
                if event.type == "OPEN_TCP_PORT":
                    key = (event.host, event.port)
                    if key not in port_probes:
                        port_probes[key] = {}
                    scheme = "https" if url.startswith("https://") else "http"
                    port_probes[key][scheme] = url

        # Only ports with BOTH schemes are subject to suppression — single-scheme
        # OPEN_TCP_PORT probes (rare, but possible) stream through normally.
        for key, schemes in port_probes.items():
            if "http" in schemes and "https" in schemes:
                paired_probe_urls[schemes["http"]] = key
                paired_probe_urls[schemes["https"]] = key

        if not stdin:
            if self._deferred_events:
                earliest = min(self._host_cooldowns.get(str(e.host), 0) for e in self._deferred_events)
                if not self._wakeup_target or earliest < self._wakeup_target:
                    delay = max(0.1, earliest - time.monotonic())
                    self._wakeup_target = earliest
                    self.helpers.create_task(self._deferred_wakeup(delay))
            return

        headers = self._build_headers()
        proxy = self.scan.http_proxy or None
        timeout = self.scan.http_timeout
        retries = self.scan.http_retries

        configs = []
        for url in stdin:
            config = blasthttp.BatchConfig(
                url,
                headers=headers,
                timeout=int(timeout),
                retries=int(retries),
                verify_certs=False,
                follow_redirects=False,
                proxy=proxy,
            )
            configs.append(config)

        # Suppress redundant https probes when http returned a real page (2xx) for
        # the same (host, port). Only a 2xx counts as "http works" -- 3xx (often
        # http-to-https redirects), 4xx (e.g. Cloudflare 400 on plain HTTP to TLS
        # port), and 5xx do NOT suppress the https probe.
        http_succeeded = {}  # key -> bool, set when http result arrives
        deferred_https = {}  # key -> result, awaiting http verdict

        async def resolve_https(key, result):
            if http_succeeded.get(key) and result.success and result.response.status != 0:
                self.debug(f"Suppressing https probe {result.url} (http already succeeded for {key})")
                return
            await self._process_result(result, stdin[result.url])

        async for result in iter_batch_results(self.client.request_batch_stream(configs, concurrency=self.threads)):
            if result.success and result.response is not None and result.response.status == 429:
                url = result.url
                host = urlparse(url).hostname
                parent_event = stdin[url]
                event_key = self._incoming_dedup_hash(parent_event)
                retry_count = self._429_retry_counts.get(event_key, 0)
                if retry_count >= self._max_429_retries:
                    self.warning(f"429 from {url} after {self._max_429_retries} retries, giving up")
                    self._429_retry_counts.pop(event_key, None)
                    continue
                retry_after = self._parse_retry_after(result.response)
                self._set_host_cooldown(host, retry_after)
                if self._defer_event(parent_event):
                    self._429_retry_counts[event_key] = retry_count + 1
                self.verbose(
                    f"429 from {host} ({url}), cooling down {retry_after}s (attempt {retry_count + 1}/{self._max_429_retries})"
                )
                continue

            # Non-429 response -- clear any retry tracking for this URL
            _retry_parent = stdin.get(result.url)
            if _retry_parent is not None:
                self._429_retry_counts.pop(self._incoming_dedup_hash(_retry_parent), None)

            key = paired_probe_urls.get(result.url)
            if key is None:
                # Non-paired URL -- emit immediately
                if _retry_parent is None:
                    self.warning(f"Unable to correlate parent event for: {result.url}")
                    continue
                await self._process_result(result, _retry_parent)
                continue

            # Paired OPEN_TCP_PORT probe
            is_http = result.url == port_probes[key]["http"]
            if is_http:
                status = result.response.status if result.response is not None else 0
                http_succeeded[key] = result.success and 200 <= status < 300
                await self._process_result(result, stdin[result.url])
                # If https for this key arrived first and was buffered, resolve it now
                pending = deferred_https.pop(key, None)
                if pending is not None:
                    await resolve_https(key, pending)
            else:  # is https
                if key in http_succeeded:
                    await resolve_https(key, result)
                else:
                    deferred_https[key] = result

        # Stream ended -- any leftover https had no http result, so emit unconditionally
        for key, result in deferred_https.items():
            await self._process_result(result, stdin[result.url])

        if self._deferred_events:
            await self._flush_deferred()
