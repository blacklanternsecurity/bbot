import logging
import requests
from time import sleep
from pathlib import Path
from requests_cache import CachedSession
from requests.adapters import HTTPAdapter
from requests_cache.backends import SQLiteCache
from requests.exceptions import RequestException

from bbot.core.errors import WordlistError, CurlError

log = logging.getLogger("bbot.core.helpers.web")


def wordlist(self, path, lines=None, **kwargs):
    if not path:
        raise WordlistError(f"Invalid wordlist: {path}")
    if not "cache_hrs" in kwargs:
        kwargs["cache_hrs"] = 720
    if self.is_url(path):
        filename = self.download(str(path), **kwargs)
        if filename is None:
            raise WordlistError(f"Unable to retrieve wordlist from {path}")
    else:
        filename = Path(path).resolve()
        if not filename.is_file():
            raise WordlistError(f"Unable to find wordlist at {path}")

    if lines is None:
        return filename
    else:
        lines = int(lines)
        with open(filename) as f:
            read_lines = f.readlines()
        cache_key = f"{filename}:{lines}"
        truncated_filename = self.cache_filename(cache_key)
        with open(truncated_filename, "w") as f:
            for line in read_lines[:lines]:
                f.write(line)
        return truncated_filename


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
        return filename.resolve()


def request(self, *args, **kwargs):
    """
    Multipurpose function for making web requests

    Supports custom sessions
        session Request.Session()

    Arguments
        cache_for (Union[None, int, float, str, datetime, timedelta]): Cache response for <int> seconds
        raise_error (bool): Whether to raise exceptions (default: False)
    """

    # we handle our own retries
    retries = kwargs.pop("retries", self.config.get("http_retries", 1))
    if getattr(self, "retry_adapter", None) is None:
        self.retry_adapter = HTTPAdapter(max_retries=0)

    raise_error = kwargs.pop("raise_error", False)

    cache_for = kwargs.pop("cache_for", None)
    if cache_for is not None:
        log.debug(f"Caching HTTP session with expire_after={cache_for}")
        try:
            session = self.cache_sessions[cache_for]
        except KeyError:
            db_path = str(self.cache_dir / "requests-cache.sqlite")
            backend = SQLiteCache(db_path=db_path)
            session = CachedSession(expire_after=cache_for, backend=backend)
            self.cache_sessions[cache_for] = session
    elif kwargs.get("session", None) is not None:
        session = kwargs.pop("session", None)
    else:
        if getattr(self, "base_session", None) is None:
            self.base_session = requests.Session()
        session = self.base_session

    session.mount("http://", self.retry_adapter)
    session.mount("https://", self.retry_adapter)

    http_timeout = self.config.get("http_timeout", 20)
    user_agent = self.config.get("user_agent", "BBOT")

    # in case of URL only, assume GET request
    if len(args) == 1:
        kwargs["url"] = args[0]
        args = []

    url = kwargs.get("url", "")

    if not args and "method" not in kwargs:
        kwargs["method"] = "GET"

    if not "timeout" in kwargs:
        kwargs["timeout"] = http_timeout

    headers = kwargs.get("headers", None)

    if headers is None:
        headers = {}
    if "User-Agent" not in headers:
        headers.update({"User-Agent": user_agent})
    # only add custom headers if the URL is in-scope
    if self.scan.in_scope(url):
        for hk, hv in self.scan.config.get("http_headers", {}).items():
            # don't clobber headers
            if hk not in headers:
                headers[hk] = hv
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
                log.verbose(f'Error requesting "{url}" ({e}), retrying...')
                sleep(1)
            else:
                if raise_error:
                    raise e


def api_page_iter(self, url, page_size=100, json=True, **requests_kwargs):
    page = 1
    offset = 0
    while 1:
        new_url = url.format(page=page, page_size=page_size, offset=offset)
        result = self.request(new_url, **requests_kwargs)
        try:
            if json:
                result = result.json()
            yield result
        except Exception:
            import traceback

            log.warning(f'Error in api_page_iter() for url: "{new_url}"')
            log.trace(traceback.format_exc())
            break
        finally:
            offset += page_size
            page += 1


def curl(self, *args, **kwargs):
    url = kwargs.get("url", "")

    if not url:
        raise CurlError("No URL supplied to CURL helper")

    curl_command = ["curl", url, "-s"]

    raw_path = kwargs.get("raw_path", False)
    if raw_path:
        curl_command.append("--path-as-is")

    # respect global ssl verify settings
    ssl_verify = self.config.get("ssl_verify")
    if ssl_verify == False:
        curl_command.append("-k")

    headers = kwargs.get("headers", {})

    ignore_bbot_global_settings = kwargs.get("ignore_bbot_global_settings", False)

    if ignore_bbot_global_settings:
        log.debug("ignore_bbot_global_settings enabled. Global settings will not be applied")
    else:
        http_timeout = self.config.get("http_timeout", 20)
        user_agent = self.config.get("user_agent", "BBOT")

        if "User-Agent" not in headers:
            headers["User-Agent"] = user_agent

        # only add custom headers if the URL is in-scope
        if self.scan.in_scope(url):
            for hk, hv in self.scan.config.get("http_headers", {}).items():
                headers[hk] = hv

        # add the timeout
        if not "timeout" in kwargs:
            timeout = http_timeout

        curl_command.append("-m")
        curl_command.append(str(timeout))

    for k, v in headers.items():
        if isinstance(v, list):
            for x in v:
                curl_command.append("-H")
                curl_command.append(f"{k}: {x}")

        else:
            curl_command.append("-H")
            curl_command.append(f"{k}: {v}")

    post_data = kwargs.get("post_data", {})
    if len(post_data.items()) > 0:
        curl_command.append("-d")
        post_data_str = ""
        for k, v in post_data.items():
            post_data_str += f"&{k}={v}"
        curl_command.append(post_data_str.lstrip("&"))

    method = kwargs.get("method", "")
    if method:
        curl_command.append("-X")
        curl_command.append(method)

    cookies = kwargs.get("cookies", "")
    if cookies:
        curl_command.append("-b")
        cookies_str = ""
        for k, v in cookies.items():
            cookies_str += f"{k}={v}; "
        curl_command.append(f'{cookies_str.rstrip(" ")}')

    path_override = kwargs.get("path_override", None)
    if path_override:
        curl_command.append("--request-target")
        curl_command.append(f"{path_override}")

    head_mode = kwargs.get("head_mode", None)
    if head_mode:
        curl_command.append("-I")

    raw_body = kwargs.get("raw_body", None)
    if raw_body:
        curl_command.append("-d")
        curl_command.append(raw_body)

    output_bytes = self.run(curl_command, text=False).stdout
    output = self.smart_decode(output_bytes)
    return output
