import logging
import xmltodict
from deepdiff import DeepDiff
from contextlib import suppress
from xml.parsers.expat import ExpatError
from bbot.errors import HttpCompareError

log = logging.getLogger("bbot.core.helpers.diff")


class _BaselineSnapshot:
    """Lightweight stand-in for a blasthttp Response held by HttpCompare.

    Stores only the fields external code accesses (status_code, headers,
    text, content) and optionally spills the body to the scan's
    BodySpillStore so the raw bytes don't pin Python heap memory for the
    lifetime of the HttpCompare instance.

    The blasthttp Headers object is kept by reference (it survives
    Response GC independently) to preserve case-insensitive lookups and
    duplicate-header semantics that DeepDiff relies on.
    """

    __slots__ = ("status_code", "headers", "_text", "_spill_key", "_spill_store")

    def __init__(self, response, spill_store=None):
        self.status_code = response.status_code
        self.headers = response.headers
        if spill_store is not None:
            body_bytes = response.body_bytes or b""
            self._spill_key = f"baseline-{id(self):x}"
            spill_store.write(self._spill_key, body_bytes)
            self._spill_store = spill_store
            self._text = None
        else:
            self._text = response.text
            self._spill_key = None
            self._spill_store = None

    @property
    def text(self):
        if self._text is not None:
            return self._text
        if self._spill_store is not None:
            body = self._spill_store.read(self._spill_key)
            if body is not None:
                return body.decode("utf-8", errors="replace")
        return ""

    @property
    def content(self):
        if self._spill_store is not None:
            return self._spill_store.read(self._spill_key) or b""
        if self._text is not None:
            return self._text.encode("utf-8", errors="replace")
        return b""

    def _cleanup(self):
        if self._spill_store is not None and self._spill_key is not None:
            self._spill_store.evict_and_delete(self._spill_key)
            self._spill_key = None

    def __del__(self):
        # Reclaim the spilled body when the snapshot is GC'd (HttpCompare
        # instances are mostly short-lived locals, so this fires promptly).
        try:
            self._cleanup()
        except Exception:
            pass


class HttpCompare:
    def __init__(
        self,
        baseline_url,
        parent_helper,
        method="GET",
        data=None,
        json=None,
        allow_redirects=False,
        include_cache_buster=True,
        headers=None,
        cookies=None,
        timeout=10,
        on_baseline_ready=None,
        baseline_url_2=None,
    ):
        self.parent_helper = parent_helper
        self.baseline_url = baseline_url
        # When set, the second baseline sample uses this URL instead of self.baseline_url,
        # so the auto-filter captures inter-URL variation (used by wildcard detection).
        self.baseline_url_2 = baseline_url_2
        self.include_cache_buster = include_cache_buster
        self.method = method
        self.data = data
        self.json = json
        self.allow_redirects = allow_redirects
        self._baselined = False
        self.headers = headers
        self.cookies = cookies
        self.timeout = 10
        # Optional async callback fired once with baseline_1 after the baseline is established.
        self.on_baseline_ready = on_baseline_ready

    @staticmethod
    def merge_dictionaries(headers1, headers2):
        if headers2 is None:
            return headers1
        else:
            merged_headers = headers1.copy()
            merged_headers.update(headers2)
            return merged_headers

    async def _baseline(self):
        if not self._baselined:
            # vanilla URL
            if self.include_cache_buster:
                url_1 = self.parent_helper.add_get_params(self.baseline_url, self.gen_cache_buster()).geturl()
            else:
                url_1 = self.baseline_url
            baseline_1 = await self.parent_helper.request(
                url_1,
                follow_redirects=self.allow_redirects,
                method=self.method,
                data=self.data,
                json=self.json,
                headers=self.headers,
                cookies=self.cookies,
                retries=2,
                timeout=self.timeout,
            )
            await self.parent_helper.sleep(0.5)
            # put random parameters in URL, headers, and cookies
            get_params = {self.parent_helper.rand_string(6): self.parent_helper.rand_string(6)}

            if self.include_cache_buster:
                get_params.update(self.gen_cache_buster())
            second_target = self.baseline_url_2 if self.baseline_url_2 else self.baseline_url
            url_2 = self.parent_helper.add_get_params(second_target, get_params).geturl()
            baseline_2 = await self.parent_helper.request(
                url_2,
                headers=self.merge_dictionaries(
                    {self.parent_helper.rand_string(6): self.parent_helper.rand_string(6)}, self.headers
                ),
                cookies=self.merge_dictionaries(
                    {self.parent_helper.rand_string(6): self.parent_helper.rand_string(6)}, self.cookies
                ),
                follow_redirects=self.allow_redirects,
                method=self.method,
                data=self.data,
                json=self.json,
                retries=2,
                timeout=self.timeout,
            )

            if baseline_1 is None or baseline_2 is None:
                log.debug("HTTP error while establishing baseline, aborting")
                baseline_1_repr = f"HTTP {baseline_1.status_code}" if baseline_1 is not None else "None"
                baseline_2_repr = f"HTTP {baseline_2.status_code}" if baseline_2 is not None else "None"
                raise HttpCompareError(
                    f"Can't get baseline from source URL: {url_1} ({baseline_1_repr}) / {url_2} ({baseline_2_repr})"
                )
            if baseline_1.status_code != baseline_2.status_code:
                log.debug("Status code not stable during baseline, aborting")
                raise HttpCompareError("Can't get baseline from source URL")

            try:
                baseline_1_json = xmltodict.parse(baseline_1.text)
                baseline_2_json = xmltodict.parse(baseline_2.text)
            except ExpatError:
                baseline_1_json = baseline_1.text.split("\n")
                baseline_2_json = baseline_2.text.split("\n")

            ddiff = DeepDiff(
                baseline_1_json, baseline_2_json, ignore_order=True, view="tree", threshold_to_diff_deeper=0
            )
            self.ddiff_filters = []

            for k in ddiff.keys():
                for x in list(ddiff[k]):
                    self.ddiff_filters.append(x.path())

            self.baseline_json = baseline_1_json
            self.baseline_ignore_headers = [
                h.lower()
                for h in [
                    "date",
                    "last-modified",
                    "content-length",
                    "connection",
                    "ETag",
                    "X-Pad",
                    "X-Backside-Transport",
                    "keep-alive",
                ]
            ]
            dynamic_headers = self.compare_headers(baseline_1.headers, baseline_2.headers)

            self.baseline_ignore_headers += [x.lower() for x in dynamic_headers]
            self._baselined = True

            if self.on_baseline_ready is not None:
                try:
                    await self.on_baseline_ready(baseline_1)
                except Exception as e:
                    log.debug(f"on_baseline_ready callback raised: {e}")

            # Replace the heavy blasthttp Response with a lightweight
            # snapshot. If the scan has a body_spill_store the body bytes
            # are written to disk and served from the LRU cache on demand.
            scan = getattr(self.parent_helper, "scan", None)
            store = getattr(scan, "body_spill_store", None)
            self.baseline = _BaselineSnapshot(baseline_1, spill_store=store)

    def gen_cache_buster(self):
        return {self.parent_helper.rand_string(6): "1"}

    def compare_headers(self, headers_1, headers_2):
        differing_headers = []

        for i, headers in enumerate((headers_1, headers_2)):
            for header, value in list(headers.items()):
                if header.lower() in self.baseline_ignore_headers:
                    with suppress(KeyError):
                        del headers[header]

        ddiff = DeepDiff(headers_1, headers_2, ignore_order=True, view="tree", threshold_to_diff_deeper=0)

        for k in ddiff.keys():
            for x in list(ddiff[k]):
                try:
                    header_value = str(x).split("'")[1]
                except (KeyError, IndexError):
                    continue
                differing_headers.append(header_value)
        return differing_headers

    def compare_body(self, content_1, content_2):
        if content_1 == content_2:
            return True

        ddiff = DeepDiff(
            content_1,
            content_2,
            ignore_order=True,
            view="tree",
            exclude_paths=self.ddiff_filters,
            threshold_to_diff_deeper=0,
        )

        if len(ddiff.keys()) == 0:
            return True
        else:
            return False

    async def compare(
        self,
        subject,
        headers=None,
        cookies=None,
        check_reflection=False,
        method="GET",
        data=None,
        json=None,
        allow_redirects=False,
        timeout=None,
    ):
        """
        Compares a URL with the baseline, with optional headers or cookies added

        Returns (match (bool), reason (str), reflection (bool),subject_response (requests response object))
            where "match" is whether the content matched against the baseline, and
                "reason" is the location of the change ("code", "body", "header", or None), and
                "reflection" is whether the value was reflected in the HTTP response
        """

        await self._baseline()

        if timeout is None:
            timeout = self.timeout

        reflection = False
        if self.include_cache_buster:
            cache_key, cache_value = list(self.gen_cache_buster().items())[0]
            url = self.parent_helper.add_get_params(subject, {cache_key: cache_value}).geturl()
        else:
            url = subject
        subject_response = await self.parent_helper.request(
            url,
            headers=headers,
            cookies=cookies,
            follow_redirects=allow_redirects,
            method=method,
            data=data,
            json=json,
            timeout=timeout,
        )

        if subject_response is None:
            # this can be caused by a WAF not liking the header, so we really aren't interested in it
            return (True, "403", reflection, subject_response)

        if check_reflection:
            for arg in (headers, cookies):
                if arg is not None:
                    for k, v in arg.items():
                        if v in subject_response.text:
                            reflection = True
                            break

            subject_params = self.parent_helper.get_get_params(subject)
            for k, v in subject_params.items():
                if self.include_cache_buster and k != cache_key:
                    for item in v:
                        if item in subject_response.text:
                            reflection = True
                            break
        diff_reasons = await self.parent_helper.run_in_executor_cpu(
            self._compare_sync,
            subject_response,
            subject,
        )

        if not diff_reasons:
            return (True, [], reflection, subject_response)
        else:
            return (False, diff_reasons, reflection, subject_response)

    def _compare_sync(self, subject_response, subject):
        """CPU-bound comparison work offloaded from the event loop."""
        try:
            subject_json = xmltodict.parse(subject_response.text)
        except ExpatError:
            subject_json = subject_response.text.split("\n")

        diff_reasons = []

        if self.baseline.status_code != subject_response.status_code:
            diff_reasons.append("code")

        different_headers = self.compare_headers(self.baseline.headers, subject_response.headers)
        if different_headers:
            diff_reasons.append("header")

        if self.compare_body(self.baseline_json, subject_json) is False:
            diff_reasons.append("body")

        return diff_reasons

    async def canary_check(self, url, mode, rounds=3):
        """
        test detection using a canary to find hosts giving bad results
        """
        await self._baseline()
        headers = None
        cookies = None
        for i in range(0, rounds):
            random_params = {self.parent_helper.rand_string(7): self.parent_helper.rand_string(7)}
            new_url = str(url)
            if mode == "getparam":
                new_url = self.parent_helper.add_get_params(url, random_params).geturl()
            elif mode == "header":
                headers = random_params
            elif mode == "cookie":
                cookies = random_params
            else:
                raise ValueError(f'Invalid mode: "{mode}", choose from: getparam, header, cookie')

            match, reasons, reflection, subject_response = await self.compare(
                new_url, headers=headers, cookies=cookies, check_reflection=True
            )

            # if a nonsense header "caused" a difference, we need to abort. We also need to abort if our canary was reflected
            if match is False or reflection is True:
                return False
        return True
