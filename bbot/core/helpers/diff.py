import logging
from deepdiff import DeepDiff
import xmltodict
from xml.parsers.expat import ExpatError
from time import sleep
from bbot.core.errors import HttpCompareError

log = logging.getLogger("bbot.core.helpers.diff")


class HttpCompare:
    def __init__(self, baseline_url, parent_helper):

        self.parent_helper = parent_helper
        self.baseline_url = baseline_url

        baseline_1 = self.parent_helper.request(self.baseline_url + self.gen_cache_buster(), allow_redirects=False)
        sleep(2)
        baseline_2 = self.parent_helper.request(
            self.baseline_url
            + self.gen_cache_buster()
            + f"&{self.parent_helper.rand_string(6)}={self.parent_helper.rand_string(6)}",
            headers={self.parent_helper.rand_string(6): self.parent_helper.rand_string(6)},
            cookies={self.parent_helper.rand_string(6): self.parent_helper.rand_string(6)},
            allow_redirects=False,
        )

        self.baseline = baseline_1

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
            "date",
            "last-modified",
            "content-length",
            "ETag",
            "X-Pad",
            "X-Backside-Transport",
        ]
        dynamic_headers = self.compare_headers(baseline_1.headers, baseline_2.headers)

        self.baseline_ignore_headers += dynamic_headers
        self.baseline_body_distance = self.compare_body(baseline_1_json, baseline_2_json)

    def gen_cache_buster(self, url=None):

        if (url != None) and ("?" in url):
            sep = "&"
        else:
            sep = "?"
        return f"{sep}{self.parent_helper.rand_string(6)}=1"

    def compare_headers(self, headers_1, headers_2):

        matched_headers = []

        for ignored_header in self.baseline_ignore_headers:
            try:
                del headers_1[ignored_header]
                log.debug(f"found ignored header {ignored_header} in headers_1 and removed")
            except KeyError:
                pass
            try:
                del headers_2[ignored_header]
                log.debug(f"found ignored header {ignored_header} in headers_2 and removed")
            except KeyError:
                pass
        ddiff = DeepDiff(headers_1, headers_2, ignore_order=True, view="tree")

        for k, v in ddiff.items():
            for x in list(ddiff[k]):
                header_value = str(x).split("'")[1]
                matched_headers.append(header_value)
        return matched_headers

    def compare_body(self, content_1, content_2):

        if content_1 == content_2:
            return True

        ddiff = DeepDiff(content_1, content_2, ignore_order=True, view="tree", exclude_paths=self.ddiff_filters)

        if len(ddiff.keys()) == 0:
            return True
        else:
            log.debug(ddiff)
            return False

    def compare(self, subject, add_headers=None, add_cookies=None):
        reflection = False
        subject_response = self.parent_helper.request(
            subject + self.gen_cache_buster(url=subject), headers=add_headers, allow_redirects=False
        )

        if not subject_response:
            # this can be caused by a WAF not liking the header, so we really arent interested in it
            return (True, "403", reflection)

        if add_headers:
            if len(add_headers) == 1:
                if list(add_headers.values())[0] in subject_response.text:
                    reflection = True

        elif add_cookies:
            if len(add_cookies) == 1:
                if list(add_cookies.values())[0] in subject_response.text:
                    reflection = True

        else:
            subject_params = subject.split("?")[1].split("&")
            if len(subject_params) == 1:
                if subject_params[0].split("=")[1] in subject_response.text:
                    reflection = True

        try:
            subject_json = xmltodict.parse(subject_response.text)

        except ExpatError:
            log.debug(f"Cant HTML parse for {subject.split('?')[0]}. Switching to text parsing as a backup")
            subject_json = subject_response.text.split("\n")

        if self.baseline.status_code != subject_response.status_code:
            log.debug(
                f"status code was different [{str(self.baseline.status_code)}] -> [{str(subject_response.status_code)}], no match"
            )
            return (False, "code", reflection)

        different_headers = self.compare_headers(self.baseline.headers, subject_response.headers)
        if different_headers:
            log.debug(f"headers were different, no match [{different_headers}]")
            return (False, "header", reflection)

        if self.compare_body(self.baseline_json, subject_json) == False:
            log.debug(f"difference in HTML body, no match")
            return (False, "body", reflection)
        return (True, None, False)
