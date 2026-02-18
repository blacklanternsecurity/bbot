import re
from datetime import datetime
from urllib.parse import parse_qs, urlparse, urlunparse

from bbot.core.helpers.misc import get_file_extension
from bbot.core.helpers.validators import clean_url
from bbot.modules.templates.subdomain_enum import subdomain_enum


class wayback(subdomain_enum):
    flags = ["passive", "subdomain-enum", "safe"]
    watched_events = ["DNS_NAME", "URL"]
    produced_events = ["URL_UNVERIFIED", "DNS_NAME", "WEB_PARAMETER", "HTTP_RESPONSE", "FINDING"]
    meta = {
        "description": "Query archive.org's Wayback Machine for subdomains, URLs, parameters, and archived content",
        "created_date": "2022-04-01",
        "author": "@liquidsec",
    }
    options = {"urls": False, "garbage_threshold": 10, "parameters": False, "archive": False}
    options_desc = {
        "urls": "emit URLs in addition to DNS_NAMEs",
        "garbage_threshold": "Dedupe similar urls if they are in a group of this size or higher (lower values == less garbage data)",
        "parameters": "emit WEB_PARAMETER events for query parameters discovered in archived URLs (requires urls=true)",
        "archive": "fetch archived versions of dead URLs from the Wayback Machine and emit HTTP_RESPONSE events (requires urls=true)",
    }
    in_scope_only = True

    base_url = "http://web.archive.org"
    url_blacklist = ["_Incapsula_Resource", "/cdn-cgi/"]

    interesting_extensions = frozenset({"zip", "sql", "bak", "env", "config"})
    interesting_compound_extensions = frozenset({"tar.gz", "tar.bz2"})

    def _is_interesting_file(self, url):
        ext = get_file_extension(url)
        if ext and ext.lower() in self.interesting_extensions:
            return True
        lower_url = url.lower()
        return any(lower_url.endswith(f".{ce}") for ce in self.interesting_compound_extensions)

    async def setup(self):
        self.urls = self.config.get("urls", False)
        self.parameters = self.config.get("parameters", False)
        if self.parameters:
            if not self.urls:
                self.hugewarning("parameters option requires urls to be enabled. Please add modules.wayback.urls=True")
                return False
            consumers = [m for m, mod in self.scan.modules.items() if "WEB_PARAMETER" in mod.watched_events]
            if not consumers:
                self.warning("Disabling parameter extraction because no modules consume WEB_PARAMETER events")
                self.parameters = False
            else:
                self.hugeinfo(
                    f"Parameter extraction enabled because the following modules consume WEB_PARAMETER events: [{', '.join(consumers)}]"
                )
        self.archive = self.config.get("archive", False)
        if self.archive and not self.urls:
            self.hugewarning("archive option requires urls to be enabled. Please add modules.wayback.urls=True")
            return False
        self.garbage_threshold = self.config.get("garbage_threshold", 10)
        self._parameter_cache = {}
        self._archive_cache = {}
        return await super().setup()

    async def handle_event(self, event):
        if event.type == "URL":
            await self._handle_url_event(event)
            return

        query = self.make_query(event)
        results, interesting_files = await self.query(query)
        for result, event_type in results:
            tags = ["from-wayback"] if event_type == "URL_UNVERIFIED" else []
            await self.emit_event(
                result,
                event_type,
                event,
                tags=tags,
                abort_if=self.abort_if,
                context=f'{{module}} queried archive.org for "{query}" and found {{event.type}}: {{event.data}}',
            )

        if interesting_files:
            await self._check_interesting_files(interesting_files, event)

        # pair unpaired archive cache entries with their parent DNS_NAME event
        if self.archive:
            paired = 0
            for url_str in list(self._archive_cache):
                if isinstance(self._archive_cache[url_str], str):
                    self._archive_cache[url_str] = (self._archive_cache[url_str], event)
                    paired += 1
            if paired:
                self.debug(f"Paired {paired} archive cache entries with parent event {event.data}")

    async def _handle_url_event(self, event):
        """Process a URL event: evict live URLs from archive cache and emit cached parameters."""
        if self.archive:
            status_code = 0
            for tag in event.tags:
                if tag.startswith("status-"):
                    try:
                        status_code = int(tag.split("-", 1)[1])
                    except ValueError:
                        pass
                    break
            # only 2xx counts as live — 3xx (e.g. http→https 301 to a 404) doesn't confirm the page exists
            if 200 <= status_code < 300:
                cleaned = clean_url(event.data).geturl()
                if self._archive_cache.pop(cleaned, None) is not None:
                    self.verbose(f"URL is live (status {status_code}), removed from archive cache: {cleaned}")

        cached = self._parameter_cache.pop(clean_url(event.data).geturl(), None)
        if cached is not None:
            flat_params, base_url = cached
            for param_name, original_value in flat_params.items():
                data = {
                    "host": str(event.host),
                    "type": "GETPARAM",
                    "name": param_name,
                    "original_value": original_value,
                    "url": base_url,
                    "description": f"HTTP Extracted Parameter [{param_name}] (wayback)",
                    "additional_params": {k: v for k, v in flat_params.items() if k != param_name},
                }
                self.verbose(f"Emitting WEB_PARAMETER [{param_name}] from archived URL {base_url}")
                await self.emit_event(
                    data,
                    "WEB_PARAMETER",
                    event,
                    tags=["from-wayback"],
                    context=f"{{module}} found query parameter [{param_name}] in archived URL and emitted {{event.type}}",
                )

    async def _check_interesting_files(self, interesting_files, event):
        """HEAD-check interesting archived files and emit FINDINGs for those that exist."""
        self.verbose(f"Checking {len(interesting_files)} interesting archived files")

        # build URL list and mapping back to metadata
        url_metadata = {}
        for cleaned_url, raw_url in interesting_files.items():
            archive_url = f"{self.base_url}/web/{raw_url}"
            url_metadata[archive_url] = (cleaned_url, raw_url)

        gen = self.helpers.request_batch(
            list(url_metadata), method="HEAD", timeout=self.http_timeout + 30, follow_redirects=True
        )
        async for archive_url, r in gen:
            cleaned_url, raw_url = url_metadata[archive_url]

            if not r or r.status_code != 200:
                status = getattr(r, "status_code", "no response") if r else "no response"
                self.debug(f"Interesting file HEAD check failed for {raw_url}: status={status}")
                continue
            # guard against soft 404s (archive.org returns text/html for missing pages)
            content_type = r.headers.get("content-type", "")
            if "text/html" in content_type:
                self.debug(f"Interesting file skipped (soft 404): {raw_url}")
                continue

            ext = get_file_extension(cleaned_url)
            desc = f"Interesting archived file found (.{ext}): {raw_url}"
            content_length = r.headers.get("content-length", "")
            if content_length:
                try:
                    size = int(content_length)
                    if size > 1024 * 1024:
                        desc += f" ({size / (1024 * 1024):.1f} MB)"
                    elif size > 1024:
                        desc += f" ({size / 1024:.1f} KB)"
                    else:
                        desc += f" ({size} bytes)"
                except ValueError:
                    pass

            self.verbose(f"Interesting archived file confirmed: {raw_url}")
            parsed = urlparse(raw_url)
            await self.emit_event(
                {"description": desc, "url": str(r.url), "host": str(parsed.hostname or "")},
                "FINDING",
                event,
                tags=["from-wayback", "archived", "interesting-file"],
                context=f"{{module}} found interesting archived file: {raw_url}",
            )

    async def _fetch_cdx(self, query):
        """Fetch URLs from the CDX API with retries. Returns the URL list or None on failure."""
        waybackurl = f"{self.base_url}/cdx/search/cdx?url={self.helpers.quote(query)}&matchType=domain&output=json&fl=original&collapse=original"
        r = None
        for i in range(3):
            r = await self.helpers.request(waybackurl, timeout=self.http_timeout + 30)
            if r:
                break
            if i < 2:
                self.verbose(f'Error connecting to archive.org for query "{query}", retrying ({i + 1}/2)')
                await self.helpers.sleep(2**i)
        if not r:
            self.warning(f'Error connecting to archive.org for query "{query}"')
            return None
        try:
            j = r.json()
            assert type(j) == list
        except Exception:
            self.warning(f'Error JSON-decoding archive.org response for query "{query}"')
            return None
        return [result[0] for result in j[1:] if result]

    def _pre_process_urls(self, urls):
        """Extract parameters, archive URLs, and interesting files from raw CDX URLs before collapse."""
        raw_url_params = {}
        archive_urls = {}
        interesting_files = {}

        for url in urls:
            try:
                parsed = urlparse(url)
                if any(bl in url for bl in self.url_blacklist):
                    continue
                if not (parsed.hostname and self.scan.in_scope(parsed.hostname)):
                    continue

                cleaned_str = clean_url(url).geturl()

                if self.archive and cleaned_str not in archive_urls:
                    archive_urls[cleaned_str] = url

                if self.urls and self._is_interesting_file(url) and cleaned_str not in interesting_files:
                    interesting_files[cleaned_str] = url

                if self.parameters and parsed.query:
                    params = parse_qs(parsed.query)
                    flat_params = {k: v[0] for k, v in params.items()}
                    if flat_params:
                        if cleaned_str not in raw_url_params:
                            raw_url_params[cleaned_str] = flat_params
                        else:
                            raw_url_params[cleaned_str].update(flat_params)
            except Exception:
                continue

        if archive_urls or interesting_files or raw_url_params:
            self.debug(
                f"Pre-processed {len(urls):,} URLs: {len(archive_urls):,} archive candidates, "
                f"{len(interesting_files):,} interesting files, {len(raw_url_params):,} URLs with parameters"
            )

        return raw_url_params, archive_urls, interesting_files

    async def query(self, query):
        results = set()

        urls = await self._fetch_cdx(query)
        if urls is None:
            return results, {}

        self.verbose(f"Found {len(urls):,} URLs for {query}")

        # filter blacklisted URLs before any further processing
        urls = [url for url in urls if not any(bl in url for bl in self.url_blacklist)]

        # pre-extract metadata from raw URLs before collapse strips query strings
        raw_url_params, archive_urls, interesting_files = {}, {}, {}
        if self.parameters or self.archive or self.urls:
            raw_url_params, archive_urls, interesting_files = self._pre_process_urls(urls)

        dns_names = set()
        collapsed_urls = 0
        start_time = datetime.now()
        # consolidate URLs to cut down on garbage data (CPU-intensive, runs in separate process)
        parsed_urls = await self.helpers.run_in_executor_mp(
            self.helpers.validators.collapse_urls,
            urls,
            threshold=self.garbage_threshold,
        )
        if self.urls:
            # deduplicate http/https variants — drop http when https also exists
            url_dedup = {}
            for parsed_url in parsed_urls:
                collapsed_urls += 1
                https_key = parsed_url._replace(scheme="https").geturl()
                if https_key not in url_dedup or parsed_url.scheme == "https":
                    url_dedup[https_key] = parsed_url
            for parsed_url in url_dedup.values():
                url_str = parsed_url.geturl()
                results.add((url_str, "URL_UNVERIFIED"))
                if self.parameters and url_str in raw_url_params:
                    base_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", ""))
                    self._parameter_cache[url_str] = (raw_url_params[url_str], base_url)
                if self.archive and url_str in archive_urls:
                    self._archive_cache[url_str] = archive_urls[url_str]
        else:
            for parsed_url in parsed_urls:
                collapsed_urls += 1
                dns_name = parsed_url.hostname
                h = hash(dns_name)
                if h not in dns_names:
                    dns_names.add(h)
                    results.add((dns_name, "DNS_NAME"))

        duration = self.helpers.human_timedelta(datetime.now() - start_time)
        self.verbose(f"Collapsed {len(urls):,} -> {collapsed_urls:,} URLs in {duration}")
        return results, interesting_files

    _wayback_head_re = re.compile(
        r'<script src="//archive\.org/includes/athena\.js".*?<!-- End Wayback Rewrite JS Include -->\s*',
        re.DOTALL,
    )
    _wayback_toolbar_re = re.compile(
        r"<!-- BEGIN WAYBACK TOOLBAR INSERT -->.*?<!-- END WAYBACK TOOLBAR INSERT -->\s*",
        re.DOTALL,
    )
    _wayback_footer_re = re.compile(
        r"<!--\s*FILE ARCHIVED ON.*",
        re.DOTALL,
    )
    # wayback rewrites all URLs in the HTML body to go through web.archive.org, e.g.:
    #   http://web.archive.org/web/20250524005847/http://example.com/page
    # this regex strips the prefix to restore original URLs
    _wayback_url_re = re.compile(r"https?://web\.archive\.org/web/\d+\w*/")
    # relative variant of the above — wayback also rewrites hrefs/srcs as relative paths, e.g.:
    #   /web/19971024185506/http://www.example.com/page
    #   /web/19971024185506im_/http://www.example.com/image.gif
    # the timestamp is always 14 digits, optionally followed by a modifier suffix (im_, js_, cs_, if_, etc.)
    _wayback_relative_url_re = re.compile(r"/web/\d{14}\w*/")
    # catch any remaining archive.org URLs not handled by the toolbar/head/footer regexes
    _wayback_stale_ref_re = re.compile(r"""(?:https?:)?//(?:web\.)?archive\.org/[^\s"'<>]*""")

    def _strip_wayback_wrapper(self, body):
        """Remove Wayback Machine artifacts from archived HTML: toolbar, scripts, footer, and URL rewrites."""
        body = self._wayback_head_re.sub("", body)
        body = self._wayback_toolbar_re.sub("", body)
        body = self._wayback_footer_re.sub("", body)
        body = self._wayback_url_re.sub("", body)
        body = self._wayback_relative_url_re.sub("", body)
        body = self._wayback_stale_ref_re.sub("", body)
        return body

    async def finish(self):
        if not self.archive or not self._archive_cache:
            return

        self.hugeinfo(f"Loading {len(self._archive_cache):,} archived URLs from the Wayback Machine")

        # build combined set of extensions to skip (blacklist + static + special)
        skip_extensions = set(self.scan.url_extension_blacklist)
        skip_extensions.update(e.lower() for e in self.scan.config.get("url_extension_static", []))
        skip_extensions.update(e.lower() for e in self.scan.config.get("url_extension_special", []))

        # build URL list and mapping back to metadata
        url_metadata = {}
        for cleaned_url, (raw_url, parent_event) in list(self._archive_cache.items()):
            ext = get_file_extension(cleaned_url)
            if ext and ext in skip_extensions:
                self.debug(f"Skipping archive fetch for {raw_url} (extension: .{ext})")
                continue
            archive_url = f"{self.base_url}/web/{raw_url}"
            url_metadata[archive_url] = (raw_url, parent_event)

        if not url_metadata:
            return

        gen = self.helpers.request_batch(list(url_metadata), timeout=self.http_timeout + 30, follow_redirects=True)
        async for archive_url, r in gen:
            raw_url, parent_event = url_metadata[archive_url]

            if not r or r.status_code != 200:
                status = getattr(r, "status_code", "no response") if r else "no response"
                self.verbose(f"Archive fetch failed for {raw_url}: status={status}")
                continue

            j = self.helpers.response_to_json(r)
            if not j:
                self.verbose(f"Failed to parse archive response for {raw_url}")
                continue

            if "body" in j:
                j["body"] = self._strip_wayback_wrapper(j["body"])

            # strip wayback-injected headers to prevent excavate from extracting archive.org artifacts
            if "header" in j:
                j["header"] = {
                    k: v for k, v in j["header"].items() if not k.startswith("x_archive_") and k != "set_cookie"
                }
            if "raw_header" in j:
                j["raw_header"] = "\r\n".join(
                    line
                    for line in j["raw_header"].split("\r\n")
                    if not line.lower().startswith(("set-cookie:", "x-archive-"))
                )

            # use the original URL so event.host returns the original host, not web.archive.org
            # this prevents internal modules (speculate, host, dnsresolve) from treating archive.org as a target
            parsed_original = urlparse(raw_url)
            hostname = str(parsed_original.hostname or "")
            port = parsed_original.port or (443 if parsed_original.scheme == "https" else 80)
            scheme = parsed_original.scheme
            # strip redundant port (e.g. :80 for http, :443 for https)
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                netloc = hostname
            else:
                netloc = f"{hostname}:{port}"
            j["url"] = urlunparse((scheme, netloc, parsed_original.path or "/", "", parsed_original.query, ""))
            # store the archive URL for provenance — downstream modules can check this field
            j["archive_url"] = str(r.url)
            # override host/port/scheme/path to match the original URL (response_to_json set them from archive.org)
            j["host"] = hostname
            j["port"] = port
            j["scheme"] = scheme
            j["path"] = parsed_original.path or "/"

            http_response = self.make_event(
                j,
                "HTTP_RESPONSE",
                parent_event,
                tags=["from-wayback", "archived"],
                context=f"{{module}} loaded archived version of {raw_url} from the Wayback Machine",
            )
            if http_response is None:
                self.verbose(f"Failed to create HTTP_RESPONSE event for {raw_url}")
                continue
            # keep the event in scope so modules like badsecrets can process the archived content
            http_response.scope_distance = 0
            self.verbose(f"Emitting archived HTTP_RESPONSE for dead URL: {raw_url}")
            await self.emit_event(http_response)
