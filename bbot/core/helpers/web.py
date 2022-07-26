import logging
import requests
from time import sleep
from requests_cache import CachedSession
from requests_cache.backends import SQLiteCache
from requests.exceptions import RequestException

log = logging.getLogger("bbot.core.helpers.web")


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
            backend = SQLiteCache(db_path=db_path)
            session = CachedSession(expire_after=cache_for, backend=backend)
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

    headers = kwargs.get("headers", None)

    if headers is None:
        headers = {}
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
                log.warning(f'Error requesting "{url}" ({e}), retrying...')
                sleep(2)
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
            log.debug(traceback.format_exc())
            break
        finally:
            offset += page_size
            page += 1
