import logging
import requests
from time import sleep
from pathlib import Path
from urllib.parse import urlparse
from requests_cache import CachedSession
from requests.exceptions import RequestException

log = logging.getLogger("bbot.core.helpers.web")

cache_dir = Path.home() / ".bbot" / "cache"
cache_dir.mkdir(parents=True, exist_ok=True)


def validate_url(self, url):
    extension_blacklist = self.config.get("url_extension_blacklist", [])
    p = urlparse(url)
    if p.path.split(".")[-1].lower() in extension_blacklist:
        return False
    return True


def download(self, url, **kwargs):
    """
    Downloads file, returns full path of filename

    Caching supported via "cache_hrs"
    """
    filename = self.cache_filename(url)
    cache_hrs = float(kwargs.pop("cache_hrs", -1))
    log.debug(f"Downloading file from {url} with cache_hrs={cache_hrs}")
    if cache_hrs > 0 and self.is_cached(url):
        log.debug(f"{url} is cached")
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
        except RequestException as e:
            log.debug(f"Failed to download {url}: {e}")
            return
        except AttributeError:
            return

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
        session = CachedSession(expire_after=cache_for)

    if kwargs.pop("session", None) or not cache_for:
        session = kwargs.pop("session", None)

    http_timeout = self.config.get("http_timeout", 20)
    user_agent = self.config.get(
        "user_agent",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1",
    )

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

    while retries == "infinite" or retries >= 0:
        try:
            logstr = f"Web request: {str(args)}, {str(kwargs)}"
            log.debug(logstr)
            if session is not None:
                response = session.request(*args, **kwargs)
            else:
                response = requests.request(*args, **kwargs)
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
