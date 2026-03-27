import re
from http.cookies import SimpleCookie
from urllib.parse import urlparse

import blasthttp

from bbot.modules.base import BaseModule


class http(BaseModule):
    watched_events = ["OPEN_TCP_PORT", "URL_UNVERIFIED", "URL"]
    produced_events = ["URL", "HTTP_RESPONSE"]
    flags = ["active", "safe", "web", "social-enum", "subdomain-enum", "cloud-enum"]
    meta = {
        "description": "Visit webpages using blasthttp (native Rust HTTP engine)",
        "created_date": "2026-03-08",
        "author": "@liquidsec",
    }

    options = {
        "threads": 50,
        "in_scope_only": True,
        "max_response_size": 5242880,
        "store_responses": False,
    }
    options_desc = {
        "threads": "Number of concurrent requests",
        "in_scope_only": "Only visit web resources that are in scope.",
        "max_response_size": "Max response size in bytes",
        "store_responses": "Save raw HTTP responses to scan folder",
    }

    scope_distance_modifier = 2
    _shuffle_incoming_queue = False
    _batch_size = 500
    _priority = 2
    # accept Javascript URLs
    accept_url_special = True

    async def setup(self):
        self.threads = self.config.get("threads", 50)
        self.max_response_size = self.config.get("max_response_size", 5242880)
        self.store_responses = self.config.get("store_responses", False)
        self.client = self.helpers.blasthttp
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
            # OPEN_TCP_PORT — probe both http and https
            host = event.host
            port = event.port
            urls = [f"http://{host}:{port}/", f"https://{host}:{port}/"]
            url_hash = hash((host, port, has_spider_max))
        if url_hash is None:
            url_hash = hash((urls[0], has_spider_max))
        return urls, url_hash

    def _incoming_dedup_hash(self, event):
        urls, url_hash = self.make_url_metadata(event)
        return url_hash

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
        parsed = urlparse(response.url)
        path = parsed.path or "/"

        # Build raw_header string (required by HTTP_RESPONSE validation)
        status_line = f"HTTP/1.1 {response.status} \r\n"
        header_lines = "\r\n".join(f"{k}: {v}" for k, v in response.headers)
        raw_header = f"{status_line}{header_lines}\r\n\r\n"

        # Build header dict (lowercase keys, comma-joined for dupes)
        header_dict = {}
        for k, v in response.headers:
            key = k.lower().replace("-", "_")
            if key in header_dict:
                header_dict[key] += f", {v}"
            else:
                header_dict[key] = v

        content_type = header_dict.get("content_type", "")
        content_length = int(header_dict.get("content_length", len(response.body_bytes)))

        # Location header for redirects (excavate uses event.redirect_location)
        location = header_dict.get("location", "")

        # Extract title from HTML
        title = ""
        body = response.body
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()

        j = {
            "url": response.url,
            "input": url_input,
            "status_code": response.status,
            "method": "GET",
            "path": path,
            "host": parsed.hostname or "",
            "raw_header": raw_header,
            "header": header_dict,
            "content_type": content_type,
            "content_length": content_length,
            "title": title,
            "body": body,
            "location": location,
            "hash": {
                "body_md5": response.hash.body_md5,
                "body_mmh3": response.hash.body_mmh3,
                "body_sha256": response.hash.body_sha256,
                "header_md5": response.hash.header_md5,
                "header_mmh3": response.hash.header_mmh3,
                "header_sha256": response.hash.header_sha256,
            },
        }

        # Include TLS certificate info when available (HTTPS responses)
        ci = response.cert_info
        if ci is not None:
            j["cert_info"] = {
                "common_name": ci.common_name,
                "sans": ci.sans,
                "emails": ci.emails,
                "issuer": ci.issuer,
                "not_before": ci.not_before,
                "not_after": ci.not_after,
                "fingerprint_sha256": ci.fingerprint_sha256,
            }

        return j

    async def handle_batch(self, *events):
        stdin = {}
        # Track dual-scheme probes from OPEN_TCP_PORT: {(host, port): {"http": url, "https": url}}
        port_probes = {}

        for event in events:
            urls, url_hash = self.make_url_metadata(event)
            for url in urls:
                stdin[url] = event
                if event.type == "OPEN_TCP_PORT":
                    key = (event.host, event.port)
                    if key not in port_probes:
                        port_probes[key] = {}
                    scheme = "https" if url.startswith("https://") else "http"
                    port_probes[key][scheme] = url

        if not stdin:
            return

        headers = self._build_headers()
        proxy = self.scan.http_proxy or None
        timeout = self.scan.blasthttp_timeout
        retries = self.scan.blasthttp_retries

        # Build batch configs
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

        # Run batch in executor to avoid blocking the event loop
        results = await self.helpers.run_in_executor(self.client.request_batch, configs, self.threads)

        # Index results by URL for the dedup check
        results_by_url = {r.url: r for r in results}

        # For OPEN_TCP_PORT probes, suppress redundant https when http already succeeded.
        # When probing an unknown port, we try both http:// and https://. If http works,
        # the port definitely speaks HTTP — the https result may be a proxy artifact
        # (intercepting proxies like Burp terminate TLS themselves, making any https://
        # URL "succeed" regardless of whether the target actually speaks TLS).
        # If http fails but https succeeds, the port genuinely speaks TLS.
        # Explicit URLs (URL_UNVERIFIED/URL) are never suppressed — this only applies
        # to speculative OPEN_TCP_PORT probes.
        suppressed_urls = set()
        for key, schemes in port_probes.items():
            http_url = schemes.get("http")
            https_url = schemes.get("https")
            if not (http_url and https_url):
                continue
            http_result = results_by_url.get(http_url)
            if http_result and http_result.success and http_result.response.status != 0:
                if https_url in results_by_url:
                    self.debug(f"Suppressing https probe {https_url} (http already succeeded: {http_url})")
                    suppressed_urls.add(https_url)

        for result in results:
            if not result.success:
                self.debug(f"blasthttp error for {result.url}: {result.error}")
                continue

            response = result.response
            status_code = response.status
            if status_code == 0:
                self.debug(f'No HTTP status code for "{result.url}"')
                continue

            if result.url in suppressed_urls:
                continue

            # Map back to parent event using the input URL
            parent_event = stdin.get(result.url, None)

            if parent_event is None:
                self.warning(f"Unable to correlate parent event for: {result.url}")
                continue

            url = response.url

            # Build JSON dict for HTTP_RESPONSE event
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
                continue

            # main URL
            tags = [f"status-{status_code}"]
            response_ip = j.get("host", "")
            if response_ip:
                tags.append(f"ip-{response_ip}")
            # grab title
            title = self.helpers.tagify(j.get("title", ""), maxlen=30)
            if title:
                tags.append(f"http-title-{title}")

            url_context = "{module} visited {event.parent.data} and got status code {event.http_status}"
            if parent_event.type == "OPEN_TCP_PORT":
                url_context += " at {event.data}"

            url_event = self.make_event(
                url,
                "URL",
                parent_event,
                tags=tags,
                context=url_context,
            )
            if url_event:
                if url_event != parent_event:
                    await self.emit_event(url_event)
                # HTTP response
                content_type = j.get("header", {}).get("content_type", "unspecified").split(";")[0]
                content_length = j.get("content_length", 0)
                content_length = self.helpers.bytes_to_human(content_length)
                await self.emit_event(
                    j,
                    "HTTP_RESPONSE",
                    url_event,
                    tags=url_event.tags,
                    context=f"HTTP_RESPONSE was {content_length} with {content_type} content type",
                )

            # Store responses if configured
            if self.store_responses:
                response_dir = self.scan.home / "http_responses"
                self.helpers.mkdir(response_dir)
                filename = f"{j['host']}.{urlparse(url).port or 443}{path.replace('/', '[slash]')}.txt"
                response_file = response_dir / filename
                response_file.write_text(j.get("raw_header", "") + j.get("body", ""))
