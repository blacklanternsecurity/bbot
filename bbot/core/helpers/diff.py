import logging
import xmltodict
from time import sleep
from deepdiff import DeepDiff
from contextlib import suppress
from xml.parsers.expat import ExpatError
from bbot.core.errors import HttpCompareError

log = logging.getLogger("bbot.core.helpers.diff")


class HttpCompare:
    def __init__(self, baseline_url, parent_helper, method="GET", allow_redirects=False, include_cache_buster=True):
        self.parent_helper = parent_helper
        self.baseline_url = baseline_url
        self.include_cache_buster = include_cache_buster

        # vanilla URL
        if self.include_cache_buster:
            url_1 = self.parent_helper.add_get_params(self.baseline_url, self.gen_cache_buster()).geturl()
        else:
            url_1 = self.baseline_url
        baseline_1 = self.parent_helper.request(url_1, allow_redirects=allow_redirects, method=method)
        sleep(1)
        # put random parameters in URL, headers, and cookies
        get_params = {self.parent_helper.rand_string(6): self.parent_helper.rand_string(6)}

        if self.include_cache_buster:
            get_params.update(self.gen_cache_buster())
        url_2 = self.parent_helper.add_get_params(self.baseline_url, get_params).geturl()
        baseline_2 = self.parent_helper.request(
            url_2,
            headers={self.parent_helper.rand_string(6): self.parent_helper.rand_string(6)},
            cookies={self.parent_helper.rand_string(6): self.parent_helper.rand_string(6)},
            allow_redirects=allow_redirects,
            method=method,
        )

        self.baseline = baseline_1

        if baseline_1 is None or baseline_2 is None:
            log.debug("HTTP error while establishing baseline, aborting")
            raise HttpCompareError("Can't get baseline from source URL")
        if baseline_1.status_code != baseline_2.status_code:
            log.debug("Status code not stable during baseline, aborting")
            raise HttpCompareError("Can't get baseline from source URL")
        try:
            baseline_1_json = xmltodict.parse(baseline_1.text)
            baseline_2_json = xmltodict.parse(baseline_2.text)
        except ExpatError:
            log.debug(f"Cant HTML parse for {baseline_url}. Switching to text parsing as a backup")
            baseline_1_json = baseline_1.text.split("\n")
            baseline_2_json = baseline_2.text.split("\n")

        ddiff = DeepDiff(baseline_1_json, baseline_2_json, ignore_order=True, view="tree")
        self.ddiff_filters = []

        for k, v in ddiff.items():
            for x in list(ddiff[k]):
                log.debug(f"Added {k} filter for path: {x.path()}")
                self.ddiff_filters.append(x.path())

        self.baseline_json = baseline_1_json

        self.baseline_ignore_headers = [
            h.lower()
            for h in [
                "date",
                "last-modified",
                "content-length",
                "ETag",
                "X-Pad",
                "X-Backside-Transport",
            ]
        ]
        dynamic_headers = self.compare_headers(baseline_1.headers, baseline_2.headers)

        self.baseline_ignore_headers += [x.lower() for x in dynamic_headers]
        self.baseline_body_distance = self.compare_body(baseline_1_json, baseline_2_json)

    def gen_cache_buster(self):
        return {self.parent_helper.rand_string(6): "1"}

    def compare_headers(self, headers_1, headers_2):
        differing_headers = []

        for i, headers in enumerate((headers_1, headers_2)):
            for header, value in list(headers.items()):
                if header.lower() in self.baseline_ignore_headers:
                    with suppress(KeyError):
                        log.debug(f'found ignored header "{header}" in headers_{i+1} and removed')
                        del headers[header]

        ddiff = DeepDiff(headers_1, headers_2, ignore_order=True, view="tree")

        for k, v in ddiff.items():
            for x in list(ddiff[k]):
                try:
                    header_value = str(x).split("'")[1]
                except KeyError:
                    continue
                differing_headers.append(header_value)
        return differing_headers

    def compare_body(self, content_1, content_2):
        if content_1 == content_2:
            return True

        ddiff = DeepDiff(content_1, content_2, ignore_order=True, view="tree", exclude_paths=self.ddiff_filters)

        if len(ddiff.keys()) == 0:
            return True
        else:
            log.debug(ddiff)
            return False

    def compare(
        self, subject, headers=None, cookies=None, check_reflection=False, method="GET", allow_redirects=False
    ):
        """
        Compares a URL with the baseline, with optional headers or cookies added

        Returns (match (bool), reason (str), reflection (bool),subject_response (requests response object))
            where "match" is whether the content matched against the baseline, and
                "reason" is the location of the change ("code", "body", "header", or None), and
                "reflection" is whether the value was reflected in the HTTP response
        """

        reflection = False
        if self.include_cache_buster:
            cache_key, cache_value = list(self.gen_cache_buster().items())[0]
            url = self.parent_helper.add_get_params(subject, {cache_key: cache_value}).geturl()
        else:
            url = subject
        subject_response = self.parent_helper.request(
            url, headers=headers, cookies=cookies, allow_redirects=allow_redirects, method=method
        )

        if not subject_response:
            # this can be caused by a WAF not liking the header, so we really arent interested in it
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
                if k != cache_key and v in subject_response.text:
                    reflection = True
                    break

        try:
            subject_json = xmltodict.parse(subject_response.text)

        except ExpatError:
            log.debug(f"Cant HTML parse for {subject.split('?')[0]}. Switching to text parsing as a backup")
            subject_json = subject_response.text.split("\n")

        diff_reasons = []

        if self.baseline.status_code != subject_response.status_code:
            log.debug(
                f"status code was different [{str(self.baseline.status_code)}] -> [{str(subject_response.status_code)}], no match"
            )
            diff_reasons.append("code")

        different_headers = self.compare_headers(self.baseline.headers, subject_response.headers)
        if different_headers:
            log.debug(f"headers were different, no match [{different_headers}]")
            diff_reasons.append("header")

        if self.compare_body(self.baseline_json, subject_json) == False:
            log.debug(f"difference in HTML body, no match")

            diff_reasons.append("body")

        if not diff_reasons:
            return (True, [], False, None)
        else:
            return (False, diff_reasons, reflection, subject_response)

    def canary_check(self, url, mode, rounds=6):
        """
        test detection using a canary to find hosts giving bad results
        """
        headers = None
        cookies = None
        for i in range(0, rounds):
            random_params = {self.parent_helper.rand_string(7): self.parent_helper.rand_string(6)}
            new_url = str(url)
            if mode == "getparam":
                new_url = self.parent_helper.add_get_params(url, random_params).geturl()
            elif mode == "header":
                headers = random_params
            elif mode == "cookie":
                cookies = random_params
            else:
                raise ValueError(f'Invalid mode: "{mode}", choose from: getparam, header, cookie')

            match, reasons, reflection, subject_response = self.compare(new_url, headers=headers, cookies=cookies)

            # a nonsense header "caused" a difference, we need to abort
            if match == False:
                return False
        return True
