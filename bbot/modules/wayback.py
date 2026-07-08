import re
import bisect
from collections import Counter
from datetime import datetime
from urllib.parse import parse_qs, urlparse, urlunparse

import orjson

from bbot.core.helpers.misc import get_file_extension
from bbot.core.helpers.validators import clean_url
from bbot.modules.templates.subdomain_enum import subdomain_enum
from bbot.core.config.models import BaseModuleConfig, Field


def _parse_cdx_response(text):
    """Parse CDX JSON response text into a URL list. Designed to run in a separate process."""
    j = orjson.loads(text)
    if not isinstance(j, list):
        return None
    return [result[0] for result in j[1:] if result]


class wayback(subdomain_enum):
    flags = ["safe", "passive", "subdomain-enum"]
    watched_events = ["DNS_NAME", "URL"]
    produced_events = ["URL_UNVERIFIED", "DNS_NAME", "WEB_PARAMETER", "HTTP_RESPONSE", "FINDING"]
    meta = {
        "description": "Query archive.org's Wayback Machine for subdomains, URLs, parameters, and archived content",
        "created_date": "2022-04-01",
        "author": "@liquidsec",
    }

    class Config(BaseModuleConfig):
        urls: bool = Field(False, description="emit URLs in addition to DNS_NAMEs")
        garbage_threshold: int = Field(
            10,
            description="Dedupe similar urls if they are in a group of this size or higher (lower values == less garbage data)",
        )
        parameters: bool = Field(
            False,
            description="emit WEB_PARAMETER events for query parameters discovered in archived URLs (requires urls=true)",
        )
        archive: bool = Field(
            False,
            description="fetch archived versions of dead URLs from the Wayback Machine and emit HTTP_RESPONSE events (requires urls=true)",
        )
        max_records: int = Field(100000, description="Maximum number of URLs to fetch from the CDX API")

    in_scope_only = True

    base_url = "http://web.archive.org"
    url_blacklist = ["_Incapsula_Resource", "/cdn-cgi/"]

    interesting_extensions = frozenset({"zip", "sql", "bak", "env", "config"})
    interesting_compound_extensions = frozenset({"tar.gz", "tar.bz2"})

    # maximum URL length before we consider it garbage (crawler traps produce absurdly long URLs)
    _max_url_length = 2000
    # if any single path segment repeats more than this many times, it's a path loop / crawler trap
    _max_path_segment_repeats = 3

    # YARA rules for filtering junk URLs out of CDX results.
    # Each rule's meta block should set category = "url_junk" and a `description`.
    # To add a new pattern, add an entry — rule names must be unique across the dict.
    _junk_url_yara_rules = {
        # Per-session bot-manager challenge URLs (Akamai-style randomized paths).
        # Counts path segments that contain all three of: uppercase, lowercase,
        # and digit/underscore. The big alternation enumerates the six
        # possible orderings of those three character classes within a segment.
        # Threshold of 2 catches every URL in the validation corpus and leaves
        # CamelCase REST paths (/api/v1/MyController/getStuff) untouched because
        # those don't contain a digit or underscore inside the camelCase segment.
        "akamai_bot_manager_url": r"""
rule akamai_bot_manager_url
{
    meta:
        author = "BBOT"
        description = "Per-session bot-manager challenge URL with random-looking path segments mixing case and digits/symbols"
        category = "url_junk"
        confidence = "HIGH"

    strings:
        $strict_seg = /\/[A-Za-z0-9_-]*([A-Z][A-Za-z0-9_-]*[a-z][A-Za-z0-9_-]*[0-9_]|[A-Z][A-Za-z0-9_-]*[0-9_][A-Za-z0-9_-]*[a-z]|[a-z][A-Za-z0-9_-]*[A-Z][A-Za-z0-9_-]*[0-9_]|[a-z][A-Za-z0-9_-]*[0-9_][A-Za-z0-9_-]*[A-Z]|[0-9_][A-Za-z0-9_-]*[A-Z][A-Za-z0-9_-]*[a-z]|[0-9_][A-Za-z0-9_-]*[a-z][A-Za-z0-9_-]*[A-Z])[A-Za-z0-9_-]*/

    condition:
        #strict_seg >= 2
}
""",
    }

    def _is_garbage_url(self, url):
        """Detect crawler-trap URLs with repeating path segments or excessive length."""
        if len(url) > self._max_url_length:
            return True
        path = urlparse(url).path
        if not path:
            return False
        segments = [s for s in path.split("/") if s]
        if not segments:
            return False
        counts = Counter(segments)
        return counts.most_common(1)[0][1] > self._max_path_segment_repeats

    # Per-URL match threshold for the YARA junk-URL rules.
    # The akamai_bot_manager_url rule requires #strict_seg >= 2.
    _junk_url_match_threshold = 2

    def _filter_urls_sync(self, urls):
        """Drop blacklisted, garbage, and YARA-junk URLs in one pass. Returns (kept, junk_dropped).

        YARA matching is batched: all candidate URLs are concatenated into
        a single UTF-8 blob (newline-delimited) and matched once, then
        string instance offsets are mapped back to individual URLs and
        counted per-URL against ``_junk_url_match_threshold``. Batching
        replaces a per-URL ``rules.match()`` call and cuts allocation
        pressure to a single match invocation.
        """
        # Phase 1: cheap filters (blacklist + garbage)
        candidates = []
        for url in urls:
            if any(bl in url for bl in self.url_blacklist):
                continue
            if self._is_garbage_url(url):
                continue
            candidates.append(url)

        if not candidates:
            return [], 0

        # Phase 2: batch YARA match on concatenated blob.
        # YARA reports match offsets in bytes, so the blob and the offset
        # table must both be built from the UTF-8 encodings. A char-count
        # offset table is misaligned for any URL containing multibyte chars.
        junk_set = set()
        encoded = [url.encode("utf-8") for url in candidates]
        blob = b"\n".join(encoded)
        matches = self._junk_url_rules.match(data=blob)
        if matches:
            offsets = []
            pos = 0
            for enc in encoded:
                offsets.append(pos)
                pos += len(enc) + 1

            match_counts = [0] * len(candidates)
            for m in matches:
                for s in m.strings:
                    for instance in s.instances:
                        idx = bisect.bisect_right(offsets, instance.offset) - 1
                        if 0 <= idx < len(candidates):
                            match_counts[idx] += 1

            threshold = self._junk_url_match_threshold
            for idx, count in enumerate(match_counts):
                if count >= threshold:
                    junk_set.add(idx)

        kept = [url for idx, url in enumerate(candidates) if idx not in junk_set]
        return kept, len(junk_set)

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
        self.max_records = self.config.get("max_records", 100000)
        self._parameter_cache = {}
        self._archive_cache = {}
        # bloom filter to deduplicate archive fetches by the response URL archive.org actually served
        # (multiple request URLs can redirect to the same archived snapshot)
        # 32M bits (~4MB) supports ~400K entries with negligible false-positive rate
        self._archive_bloom = self.helpers.bloom_filter(32000000)
        self._junk_url_rules = self.helpers.yara.compile(source="\n".join(self._junk_url_yara_rules.values()))
        return await super().setup()

    def _incoming_dedup_hash(self, event):
        # URL events are handled differently (parameter/archive cache eviction),
        # so they should not be deduplicated by the subdomain_enum strategy
        if event.type == "URL":
            return hash(event.url), "url_event"
        return super()._incoming_dedup_hash(event)

    async def filter_event(self, event):
        # URL events are handled separately and don't need subdomain_enum's wildcard/cloud filtering
        if event.type == "URL":
            return True
        return await super().filter_event(event)

    async def handle_event(self, event):
        if event.type == "URL":
            await self._handle_url_event(event)
            return

        if await self._is_http_wildcard_host(event) is True:
            self.debug(f"Skipping wayback query for {event.host}: HTTP wildcard responder")
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
                context=f'{{module}} queried archive.org for "{query}" and found {{event.type}}: {{event.pretty_string}}',
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
                cleaned = clean_url(event.url).geturl()
                if self._archive_cache.pop(cleaned, None) is not None:
                    self.verbose(f"URL is live (status {status_code}), removed from archive cache: {cleaned}")

        cached = self._parameter_cache.pop(clean_url(event.url).geturl(), None)
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

        for archive_url, (cleaned_url, raw_url) in url_metadata.items():
            try:
                r = await self.helpers.request(
                    archive_url, method="HEAD", timeout=self.http_timeout_infrastructure + 30, follow_redirects=True
                )
            except Exception as e:
                self.debug(f"Interesting file HEAD check error for {raw_url}: {e}")
                continue

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
                {
                    "description": desc,
                    "severity": "LOW",
                    "name": "Interesting Archived File",
                    "confidence": "MEDIUM",
                    "url": str(r.url),
                    "host": str(parsed.hostname or ""),
                },
                "FINDING",
                event,
                tags=["from-wayback", "archived", "interesting-file"],
                context=f"{{module}} found interesting archived file: {raw_url}",
            )

    # CDX API filters applied server-side to reduce response size
    _cdx_filters = (
        "filter=!statuscode:404",
        "filter=!statuscode:301",
        "filter=!statuscode:302",
        "filter=!mimetype:image/.*",
        "filter=!mimetype:text/css",
        "filter=!mimetype:warc/revisit",
    )

    async def _fetch_cdx(self, query):
        """Fetch URLs from the CDX API with retries and 429 handling. Returns the URL list or None on failure."""
        params = f"url={self.helpers.quote(query)}&matchType=domain&output=json&fl=original&collapse=original"
        params += f"&limit={self.max_records}"
        params += "&" + "&".join(self._cdx_filters)
        waybackurl = f"{self.base_url}/cdx/search/cdx?{params}"
        r = None
        last_error = None
        for i in range(3):
            try:
                r = await self.helpers.request(
                    waybackurl, timeout=self.http_timeout_infrastructure + 60, raise_error=True
                )
            except Exception as e:
                last_error = str(e)
                r = None
            if r is not None:
                if r.status_code == 200:
                    break
                if r.status_code == 429:
                    retry_after = r.headers.get("retry-after", "")
                    try:
                        delay = min(int(retry_after), 120)
                    except (ValueError, TypeError):
                        delay = self._archive_429_default_delay
                    last_error = "HTTP 429 rate limited"
                    self.verbose(f'Archive.org rate limit (429) for CDX query "{query}", sleeping {delay}s')
                    await self.helpers.sleep(delay)
                    r = None
                    continue
                last_error = f"HTTP status {r.status_code}"
                r = None
            if i < 2:
                self.verbose(
                    f'Error connecting to archive.org for query "{query}" ({last_error}), retrying ({i + 1}/2)'
                )
                await self.helpers.sleep(2**i)
        if r is None:
            self.warning(f'Error connecting to archive.org for query "{query}": {last_error}')
            return None
        # parse JSON + extract URLs off the event loop
        # (CDX responses can contain 100k+ entries)
        try:
            urls = await self.helpers.run_in_executor_cpu(_parse_cdx_response, r.text)
        except Exception:
            urls = None
        if urls is None:
            self.warning(f'Error JSON-decoding archive.org response for query "{query}"')
            return None
        return urls

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
                if self._is_garbage_url(url):
                    continue
                if not (parsed.hostname and self.scan.in_scope(parsed.hostname)):
                    continue
                # skip non-HTTP URLs (e.g. ftp:// archived by the Wayback Machine)
                if parsed.scheme not in ("http", "https"):
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

        # filter blacklisted, garbage, and junk URLs before any further processing
        # (one bulk executor pass, since CDX responses can contain 100K+ URLs)
        urls, junk_dropped = await self.helpers.run_in_executor_cpu(self._filter_urls_sync, urls)
        if junk_dropped:
            self.verbose(f"Filtered {junk_dropped:,} junk URLs via YARA rules for {query}")

        # pre-extract metadata from raw URLs before collapse strips query strings
        raw_url_params, archive_urls, interesting_files = {}, {}, {}
        if self.parameters or self.archive or self.urls:
            raw_url_params, archive_urls, interesting_files = self._pre_process_urls(urls)

        if not urls:
            return results, interesting_files

        dns_names = set()
        collapsed_urls = 0
        start_time = datetime.now()
        # consolidate URLs to cut down on garbage data (CPU-intensive, runs off the event loop)
        parsed_urls = await self.helpers.run_in_executor_cpu(
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

    _archive_per_request_retries = 3
    _archive_batch_retries = 1
    _archive_error_delay = 3  # initial backoff seconds after a failed request
    _archive_429_default_delay = 30  # default delay on 429 when no retry-after header

    async def finish(self):
        if not self.archive or not self._archive_cache:
            return

        self.verbose(f"Loading {len(self._archive_cache):,} archived URLs from the Wayback Machine")

        # build combined set of extensions to skip (blacklist + static + special)
        skip_extensions = set(self.scan.url_extension_blacklist)
        skip_extensions.update(e.lower() for e in self.scan.config.get("url_extension_static", []))
        skip_extensions.update(e.lower() for e in self.scan.config.get("url_extension_special", []))

        # build URL list and mapping back to metadata
        url_metadata = {}
        for cleaned_url, value in list(self._archive_cache.items()):
            if not isinstance(value, tuple):
                self.debug(f"Skipping unpaired archive entry: {cleaned_url}")
                continue
            raw_url, parent_event = value
            ext = get_file_extension(cleaned_url)
            if ext and ext in skip_extensions:
                self.debug(f"Skipping archive fetch for {raw_url} (extension: .{ext})")
                continue
            archive_url = f"{self.base_url}/web/{raw_url}"
            url_metadata[archive_url] = (raw_url, parent_event)

        if not url_metadata:
            return

        total = len(url_metadata)
        self.info(f"Fetching {total:,} archived pages from archive.org")

        failed, succeeded, processed = await self._fetch_archive_batch(url_metadata, total, 0)

        # batch-level retry as safety net (per-request retry handles most transient errors,
        # but a temporary outage window could still leave a batch of failures)
        for retry_num in range(1, self._archive_batch_retries + 1):
            if not failed:
                break
            delay = 30 * retry_num
            self.info(
                f"Retrying {len(failed):,} failed archive fetches (batch retry {retry_num}/{self._archive_batch_retries}, "
                f"backoff {delay}s)"
            )
            await self.helpers.sleep(delay)
            retry_metadata = {url: url_metadata[url] for url in failed}
            new_failed, new_succeeded, processed = await self._fetch_archive_batch(
                retry_metadata, total, processed - len(failed)
            )
            succeeded += new_succeeded
            failed = new_failed

        if failed:
            self.warning(f"Failed to fetch {len(failed):,} archived URLs after retries")
        self.info(f"Archive loading complete: {succeeded:,}/{total:,} succeeded")

    async def _fetch_archive_batch(self, url_metadata, total, processed_offset):
        """Fetch a batch of archive URLs with per-request retry and rate-limit handling.

        Returns (failed_urls, success_count, processed_count).
        """
        failed = []
        succeeded = 0
        skipped = 0
        processed = processed_offset

        for archive_url, (raw_url, parent_event) in url_metadata.items():
            processed += 1

            # HEAD pre-check: resolve redirects cheaply to check for duplicates
            # before downloading the full response body
            resolved_url = await self._resolve_archive_url(archive_url, raw_url)
            if resolved_url is not None and resolved_url in self._archive_bloom:
                self.verbose(f"Skipping duplicate archive response for {raw_url} (resolved URL: {resolved_url})")
                skipped += 1
                if processed % 50 == 0 or processed == total:
                    self.verbose(
                        f"Archive progress: {processed:,}/{total:,} ({succeeded:,} succeeded, {len(failed):,} failed, {skipped:,} skipped)"
                    )
                continue

            r = await self._fetch_single_archive_url(archive_url, raw_url)

            if not r or r.status_code != 200:
                status = getattr(r, "status_code", "no response") if r else "no response"
                self.verbose(f"Archive fetch failed for {raw_url} after retries: status={status}")
                failed.append(archive_url)
                continue

            if await self._process_archive_response(r, raw_url, parent_event):
                succeeded += 1

            if processed % 50 == 0 or processed == total:
                self.verbose(
                    f"Archive progress: {processed:,}/{total:,} ({succeeded:,} succeeded, {len(failed):,} failed, {skipped:,} skipped)"
                )

        return failed, succeeded, processed

    async def _resolve_archive_url(self, archive_url, raw_url):
        """HEAD request to resolve the final URL after redirects, for bloom filter pre-check.

        Returns the resolved URL string, or None if the HEAD request fails.
        """
        try:
            r = await self.helpers.request(
                archive_url,
                method="HEAD",
                timeout=self.http_timeout_infrastructure + 30,
                follow_redirects=True,
                raise_error=True,
            )
        except Exception as e:
            self.debug(f"HEAD pre-check failed for {raw_url}: {e}")
            return None
        if r.status_code == 429:
            retry_after = r.headers.get("retry-after", "")
            try:
                delay = min(int(retry_after), 120)
            except (ValueError, TypeError):
                delay = self._archive_429_default_delay
            self.verbose(f"Archive.org rate limit (429) during HEAD pre-check for {raw_url}, sleeping {delay}s")
            await self.helpers.sleep(delay)
            return None
        if r.status_code == 200:
            return str(r.url)
        return None

    async def _fetch_single_archive_url(self, archive_url, raw_url):
        """Fetch a single archive URL with per-request retry, 429 handling, and backoff.

        archive.org rate-limits CDX at ~60 req/min and blocks the IP at the firewall
        if 429 responses are ignored for more than a minute. We must respect 429 + Retry-After.
        """
        r = None
        for attempt in range(self._archive_per_request_retries):
            try:
                r = await self.helpers.request(
                    archive_url, timeout=self.http_timeout_infrastructure + 60, follow_redirects=True, raise_error=True
                )
            except Exception as e:
                r = None
                if attempt < self._archive_per_request_retries - 1:
                    delay = self._archive_error_delay * (2**attempt)
                    self.verbose(
                        f"Archive fetch error for {raw_url} (attempt {attempt + 1}/{self._archive_per_request_retries}): "
                        f"{e} -- retrying in {delay}s"
                    )
                    await self.helpers.sleep(delay)
                else:
                    self.verbose(
                        f"Archive fetch error for {raw_url} (final attempt {attempt + 1}/{self._archive_per_request_retries}): {e}"
                    )
                continue

            if r.status_code == 429:
                retry_after = r.headers.get("retry-after", "")
                try:
                    delay = min(int(retry_after), 120)
                except (ValueError, TypeError):
                    delay = self._archive_429_default_delay
                self.verbose(f"Archive.org rate limit (429) for {raw_url}, sleeping {delay}s")
                await self.helpers.sleep(delay)
                r = None
                continue

            # any other status code (200, 404, 503, etc.) is a definitive answer — return it
            return r

        return r

    async def _process_archive_response(self, r, raw_url, parent_event):
        """Process a successful archive.org response into an HTTP_RESPONSE event. Returns True on success."""
        # deduplicate by the actual response URL archive.org served (after redirects)
        # multiple request URLs can redirect to the same archived snapshot
        response_url = str(r.url)
        if response_url in self._archive_bloom:
            self.verbose(f"Skipping duplicate archive response for {raw_url} (response URL: {response_url})")
            return False
        self._archive_bloom.add(response_url)

        j = self.helpers.response_to_json(r)
        if not j:
            self.verbose(f"Failed to parse archive response for {raw_url}")
            return False

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
            return False
        # keep the event in scope so modules like badsecrets can process the archived content
        http_response.scope_distance = 0
        self.verbose(f"Emitting archived HTTP_RESPONSE for dead URL: {raw_url}")
        await self.emit_event(http_response)
        return True
