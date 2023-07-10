import re
import ssl
import httpx
import logging
import traceback
from pathlib import Path
from bs4 import BeautifulSoup

from bbot.core.errors import WordlistError, CurlError
from bbot.core.helpers.ratelimiter import RateLimiter

log = logging.getLogger("bbot.core.helpers.web")


class BBOTAsyncClient(httpx.AsyncClient):
    def __init__(self, *args, **kwargs):
        self._bbot_scan = kwargs.pop("_bbot_scan")

        # timeout
        http_timeout = self._bbot_scan.config.get("http_timeout", 20)
        if not "timeout" in kwargs:
            kwargs["timeout"] = http_timeout

        # headers
        headers = kwargs.get("headers", None)
        if headers is None:
            headers = {}
        # user agent
        user_agent = self._bbot_scan.config.get("user_agent", "BBOT")
        if "User-Agent" not in headers:
            headers["User-Agent"] = user_agent
        kwargs["headers"] = headers
        # proxy
        proxies = self._bbot_scan.config.get("http_proxy", None)
        kwargs["proxies"] = proxies

        http_debug = self._bbot_scan.config.get("http_debug", None)
        if http_debug:
            log.debug(f"Creating AsyncClient: {args}, {kwargs}")

        super().__init__(*args, **kwargs)

    def build_request(self, *args, **kwargs):
        request = super().build_request(*args, **kwargs)
        # add custom headers if the URL is in-scope
        if self._bbot_scan.in_scope(str(request.url)):
            for hk, hv in self._bbot_scan.config.get("http_headers", {}).items():
                # don't clobber headers
                if hk not in request.headers:
                    request.headers[hk] = hv
        return request


class WebHelper:
    """
    For making HTTP requests
    """

    client_options = (
        "auth",
        "params",
        "headers",
        "retries",
        "cookies",
        "verify",
        "timeout",
        "follow_redirects",
        "max_redirects",
    )

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        self.http_debug = self.parent_helper.config.get("http_debug", False)
        self.ssl_verify = self.parent_helper.config.get("ssl_verify", False)
        self.web_requests_per_second = self.parent_helper.config.get("web_requests_per_second", 50)
        self.web_rate_limiter = RateLimiter(self.web_requests_per_second, "Web")

    def AsyncClient(self, *args, **kwargs):
        kwargs["_bbot_scan"] = self.parent_helper.scan
        retries = kwargs.pop("retries", self.parent_helper.config.get("http_retries", 1))
        kwargs["transport"] = httpx.AsyncHTTPTransport(retries=retries, verify=self.ssl_verify)
        kwargs["verify"] = self.ssl_verify
        return BBOTAsyncClient(*args, **kwargs)

    async def request(self, *args, **kwargs):
        raise_error = kwargs.pop("raise_error", False)
        # TODO: use this
        cache_for = kwargs.pop("cache_for", None)  # noqa

        # allow vs follow, httpx why??
        allow_redirects = kwargs.pop("allow_redirects", None)
        if allow_redirects is not None and "follow_redirects" not in kwargs:
            kwargs["follow_redirects"] = allow_redirects

        # in case of URL only, assume GET request
        if len(args) == 1:
            kwargs["url"] = args[0]
            args = []

        if not args and "method" not in kwargs:
            kwargs["method"] = "GET"

        client_kwargs = {}
        for k in list(kwargs):
            if k in self.client_options:
                v = kwargs.pop(k)
                client_kwargs[k] = v
        async with self.AsyncClient(**client_kwargs) as client:
            try:
                if self.http_debug:
                    logstr = f"Web request: {str(args)}, {str(kwargs)}"
                    log.debug(logstr)
                async with self.web_rate_limiter:
                    response = await client.request(*args, **kwargs)
                if self.http_debug:
                    log.debug(
                        f"Web response: {response} (Length: {len(response.content)}) headers: {response.headers}"
                    )
                return response
            except httpx.RequestError as e:
                log.debug(f"Error with request: {e}")
                log.trace(traceback.format_exc())
                if raise_error:
                    raise
            except ssl.SSLError as e:
                log.debug(f"SSL error with request: {e}")
                log.trace(traceback.format_exc())

    async def download(self, url, **kwargs):
        """
        Downloads file, returns full path of filename
        If download failed, returns None

        Caching supported via "cache_hrs"
        """
        success = False
        filename = kwargs.pop("filename", self.parent_helper.cache_filename(url))
        cache_hrs = float(kwargs.pop("cache_hrs", -1))
        log.debug(f"Downloading file from {url} with cache_hrs={cache_hrs}")
        if cache_hrs > 0 and self.parent_helper.is_cached(url):
            log.debug(f"{url} is cached at {self.parent_helper.cache_filename(url)}")
            success = True
        else:
            # kwargs["raise_error"] = True
            # kwargs["stream"] = True
            if not "method" in kwargs:
                kwargs["method"] = "GET"
            try:
                async with self.AsyncClient().stream(url=url, **kwargs) as response:
                    status_code = getattr(response, "status_code", 0)
                    log.debug(f"Download result: HTTP {status_code}")
                    if status_code != 0:
                        response.raise_for_status()
                        with open(filename, "wb") as f:
                            async for chunk in response.aiter_bytes(chunk_size=8192):
                                f.write(chunk)
                        success = True
            except httpx.HTTPError as e:
                log.warning(f"Failed to download {url}: {e}")
                return

        if success:
            return filename.resolve()

    async def wordlist(self, path, lines=None, **kwargs):
        if not path:
            raise WordlistError(f"Invalid wordlist: {path}")
        if not "cache_hrs" in kwargs:
            kwargs["cache_hrs"] = 720
        if self.parent_helper.is_url(path):
            filename = await self.download(str(path), **kwargs)
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
            truncated_filename = self.parent_helper.cache_filename(cache_key)
            with open(truncated_filename, "w") as f:
                for line in read_lines[:lines]:
                    f.write(line)
            return truncated_filename

    async def api_page_iter(self, url, page_size=100, json=True, next_key=None, **requests_kwargs):
        """
        An async generator to fetch and loop through API pages.

        This function keeps calling the API with the provided URL, increasing the page number each time, and spits out
        the results one page at a time. It's perfect for APIs that split their data across multiple pages.

        Args:
            url (str): The API endpoint. May contain placeholders for 'page' and 'page_size'.
            page_size (int, optional): How many items you want per page. Defaults to 100.
            json (bool, optional): If True, we'll try to convert the response to JSON. Defaults to True.
            next_key (callable, optional): If your API has a weird way to get to the next page, give us a function
                                           that takes the response and spits out the new URL. Defaults to None.
            **requests_kwargs: Any other stuff you want to pass to the request.

        Yields:
            If 'json' is True, you'll get a dict with the API's response, else you'll get the raw response.

        Note:
            You MUST break out of the loop when you stop getting useful results! Otherwise it will loop forever.

        Example:
            Here's a quick example of how to use this:
            ```
            agen = api_page_iter('https://api.example.com/data?page={page}&page_size={page_size}')
            try:
                async for page in agen:
                    subdomains = json["subdomains"]
                    self.hugesuccess(subdomains)
                    if not subdomains:
                        break
            finally:
                agen.aclose()
            ```
        """
        page = 1
        offset = 0
        result = None
        while 1:
            if result and callable(next_key):
                try:
                    new_url = next_key(result)
                except Exception as e:
                    log.debug(f"Failed to extract next page of results from {url}: {e}")
                    log.debug(traceback.formate_exc())
            else:
                new_url = url.format(page=page, page_size=page_size, offset=offset)
            result = await self.request(new_url, **requests_kwargs)
            try:
                if json:
                    result = result.json()
                yield result
            except Exception:
                log.warning(f'Error in api_page_iter() for url: "{new_url}"')
                log.trace(traceback.format_exc())
                break
            finally:
                offset += page_size
                page += 1

    async def curl(self, *args, **kwargs):
        url = kwargs.get("url", "")

        if not url:
            raise CurlError("No URL supplied to CURL helper")

        curl_command = ["curl", url, "-s"]

        raw_path = kwargs.get("raw_path", False)
        if raw_path:
            curl_command.append("--path-as-is")

        # respect global ssl verify settings
        if self.ssl_verify == False:
            curl_command.append("-k")

        headers = kwargs.get("headers", {})

        ignore_bbot_global_settings = kwargs.get("ignore_bbot_global_settings", False)

        if ignore_bbot_global_settings:
            log.debug("ignore_bbot_global_settings enabled. Global settings will not be applied")
        else:
            http_timeout = self.parent_helper.config.get("http_timeout", 20)
            user_agent = self.parent_helper.config.get("user_agent", "BBOT")

            if "User-Agent" not in headers:
                headers["User-Agent"] = user_agent

            # only add custom headers if the URL is in-scope
            if self.parent_helper.scan.in_scope(url):
                for hk, hv in self.parent_helper.scan.config.get("http_headers", {}).items():
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

        output = (await self.parent_helper.run(curl_command)).stdout
        return output


user_keywords = [re.compile(r, re.I) for r in ["user", "login", "email"]]
pass_keywords = [re.compile(r, re.I) for r in ["pass"]]


def is_login_page(html):
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception as e:
        log.debug(f"Error parsing html: {e}")
        return False

    forms = soup.find_all("form")

    # first, check for obvious password fields
    for form in forms:
        if form.find_all("input", {"type": "password"}):
            return True

    # next, check for forms that have both a user-like and password-like field
    for form in forms:
        user_fields = sum(bool(form.find_all("input", {"name": r})) for r in user_keywords)
        pass_fields = sum(bool(form.find_all("input", {"name": r})) for r in pass_keywords)
        if user_fields and pass_fields:
            return True
    return False
