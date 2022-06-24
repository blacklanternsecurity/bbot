import logging
import requests
from time import sleep
from urllib.parse import urlparse
from requests_cache import CachedSession
from requests.exceptions import RequestException


from deepdiff import DeepDiff
import xmltojson
import json
from xml.parsers.expat import ExpatError

log = logging.getLogger("bbot.core.helpers.web")


def validate_url(self, url):
    extension_blacklist = self.config.get("url_extension_blacklist", [])
    p = urlparse(url)
    if p.path.split(".")[-1].lower() in extension_blacklist:
        return False
    return True


def download(self, url, **kwargs):
    """
    Downloads file, returns full path of filename
    If download failed, returns None

    Caching supported via "cache_hrs"
    """
    success = False
    filename = self.cache_filename(url)
    cache_hrs = float(kwargs.pop("cache_hrs", -1))
    log.debug(f"Downloading file from {url} with cache_hrs={cache_hrs}")
    if cache_hrs > 0 and self.is_cached(url):
        log.debug(f"{url} is cached")
        success = True
    else:
        method = kwargs.get("method", "GET")
        try:
            with self.request(method=method, url=url, stream=True, raise_error=True, **kwargs) as response:
                status_code = getattr(response, "status_code", 0)
                log.debug(f"Download result: HTTP {status_code}")
                if status_code != 0:
                    response.raise_for_status()
                    with open(filename, "wb") as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    success = True
        except RequestException as e:
            log.warning(f"Failed to download {url}: {e}")
            return
        except AttributeError:
            return

    if success:
        return str(filename.resolve())


def request(self, *args, **kwargs):
    """
    Multipurpose function for making web requests

    Supports custom sessions
        session Request.Session()

    Arguments
        cache_for (Union[None, int, float, str, datetime, timedelta]): Cache response for <int> seconds
        raise_error (bool): Whether to raise exceptions (default: False)
    """

    raise_error = kwargs.pop("raise_error", False)

    cache_for = kwargs.pop("cache_for", None)
    if cache_for is not None:
        log.debug(f"Caching HTTP session with expire_after={cache_for}")
        try:
            session = self.cache_sessions[cache_for]
        except KeyError:
            db_path = str(self.cache_dir / "requests-cache.sqlite")
            session = CachedSession(expire_after=cache_for, db_path=db_path)
            self.cache_sessions[cache_for] = session

    if kwargs.pop("session", None) or not cache_for:
        session = kwargs.pop("session", None)

    http_timeout = self.config.get("http_timeout", 20)
    user_agent = self.config.get("user_agent", "BBOT")

    # in case of URL only, assume GET request
    if len(args) == 1:
        kwargs["url"] = args[0]
        args = []

    url = kwargs.get("url", "")
    retries = kwargs.pop("retries", 0)

    if not args and "method" not in kwargs:
        kwargs["method"] = "GET"

    if not "timeout" in kwargs:
        kwargs["timeout"] = http_timeout

    headers = kwargs.get("headers", {})

    if "User-Agent" not in headers:
        headers.update({"User-Agent": user_agent})
    kwargs["headers"] = headers

    http_debug = self.config.get("http_debug", False)
    while retries == "infinite" or retries >= 0:
        try:
            if http_debug:
                logstr = f"Web request: {str(args)}, {str(kwargs)}"
                log.debug(logstr)
            if session is not None:
                response = session.request(*args, **kwargs)
            else:
                response = requests.request(*args, **kwargs)
            if http_debug:
                log.debug(f"Web response: {response} (Length: {len(response.content)}) headers: {response.headers}")
            return response
        except RequestException as e:
            log.debug(f"Error with request: {e}")
            if retries != "infinite":
                retries -= 1
            if retries == "infinite" or retries >= 0:
                log.warning(f'Error requesting "{url}", retrying...')
                sleep(2)
            else:
                if raise_error:
                    raise e


class HttpCompare:
    def __init__(self, baseline_url):
        self.baseline_url = baseline_url

        baseline_1 = requests.get(self.baseline_url, verify=False)
        sleep(2)
        baseline_2 = requests.get(self.baseline_url, verify=False)
        self.baseline = baseline_1

        if baseline_1.status_code != baseline_2.status_code:
            raise Exception("Can't get baseline from source URL")
        try:
            baseline_1_json = json.loads(xmltojson.parse(baseline_1.text))
            baseline_2_json = json.loads(xmltojson.parse(baseline_2.text))
        except ExpatError:
            log.debug(f"Cant HTML parse for {baseline_url}. Switching to text parsing as a backup")
            baseline_1_json = baseline_1.text.split("\n")
            baseline_2_json = baseline_2.text.split("\n")

        self.baseline_json = baseline_1_json

        self.baseline_ignore_headers = ["date", "last-modified", "content-length"]
        dynamic_headers = self.compare_headers(baseline_1.headers, baseline_2.headers)

        self.baseline_ignore_headers += dynamic_headers
        self.baseline_body_distance = self.compare_body(baseline_1_json, baseline_2_json)

    def compare_headers(self, headers_1, headers_2):

        matched_headers = []

        for ignored_header in self.baseline_ignore_headers:
            try:
                del headers_1[ignored_header]
            except KeyError:
                pass
            try:
                del headers_2[ignored_header]
            except KeyError:
                pass
        ddiff = DeepDiff(headers_1, headers_2, ignore_order=True, view="tree")

        try:
            for x in list(ddiff["dictionary_item_added"]):
                header_value = str(x).split("'")[1]
                matched_headers.append(header_value)
        except KeyError:
            pass

        try:
            for x in list(ddiff["values_changed"]):
                header_value = str(x).split("'")[1]
                matched_headers.append(header_value)
        except KeyError:
            pass

        try:
            for x in list(ddiff["dictionary_item_removed"]):
                header_value = str(x).split("'")[1]
                matched_headers.append(header_value)

        except KeyError:
            pass

        return matched_headers

    def compare_body(self, content_1, content_2):

        # experiment with either a distance value or finding the differences by offset
        if content_1 == content_2:
            return 0.0
        ddiff = DeepDiff(content_1, content_2, get_deep_distance=True, cutoff_intersection_for_pairs=1)
        return ddiff["deep_distance"]

    def compare(self, subject, add_headers=None, add_cookie=None):
        subject_response = requests.get(subject, headers=add_headers, verify=False)

        try:
            subject_json = json.loads(xmltojson.parse(subject_response.text))
        except ExpatError:
            log.debug(f"Cant HTML parse for {subject}. Switching to text parsing as a backup")
            subject_json = subject_response.text.split("\n")

        if self.baseline.status_code != subject_response.status_code:
            log.debug(
                f"status code was different [{str(self.baseline.status_code)}] -> [{str(subject_response.status_code)}], no match"
            )
            return False

        different_headers = self.compare_headers(self.baseline.headers, subject_response.headers)
        if different_headers:
            log.debug(f"headers were different, no match [{different_headers}]")
            return False

        subject_body_distance = self.compare_body(self.baseline_json, subject_json)

        # probabaly add a little bit of give here
        if self.baseline_body_distance != subject_body_distance:
            log.debug("different body distance, no match")
            return False
        return True
