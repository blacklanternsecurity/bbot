import httpx
import logging
from httpx._models import Cookies

log = logging.getLogger("bbot.core.helpers.web.client")


class DummyCookies(Cookies):
    def extract_cookies(self, *args, **kwargs):
        pass


class BBOTAsyncClient(httpx.AsyncClient):
    """
    A subclass of httpx.AsyncClient tailored with BBOT-specific configurations and functionalities.
    This class provides rate limiting, logging, configurable timeouts, user-agent customization, custom
    headers, and proxy settings. Additionally, it allows the disabling of cookies, making it suitable
    for use across an entire scan.

    Attributes:
        _bbot_scan (object): BBOT scan object containing configuration details.
        _persist_cookies (bool): Flag to determine whether cookies should be persisted across requests.

    Examples:
        >>> async with BBOTAsyncClient(_bbot_scan=bbot_scan_object) as client:
        >>>     response = await client.request("GET", "https://example.com")
        >>>     print(response.status_code)
        200
    """

    @classmethod
    def from_config(cls, config, target, *args, **kwargs):
        kwargs["_config"] = config
        kwargs["_target"] = target
        web_config = config.get("web", {})
        retries = kwargs.pop("retries", web_config.get("http_retries", 1))
        ssl_verify = web_config.get("ssl_verify", False)
        if ssl_verify is False:
            from .ssl_context import ssl_context_noverify

            ssl_verify = ssl_context_noverify
        kwargs["transport"] = httpx.AsyncHTTPTransport(retries=retries, verify=ssl_verify)
        kwargs["verify"] = ssl_verify
        return cls(*args, **kwargs)

    def __init__(self, *args, **kwargs):
        self._config = kwargs.pop("_config")
        self._target = kwargs.pop("_target")

        self._web_config = self._config.get("web", {})
        http_debug = self._web_config.get("debug", None)
        if http_debug:
            log.trace(f"Creating AsyncClient: {args}, {kwargs}")

        self._persist_cookies = kwargs.pop("persist_cookies", False)

        # timeout
        http_timeout = self._web_config.get("http_timeout", 20)
        if "timeout" not in kwargs:
            kwargs["timeout"] = http_timeout

        # headers
        headers = kwargs.get("headers", None)
        if headers is None:
            headers = {}

        # cookies
        cookies = kwargs.get("cookies", None)
        if cookies is None:
            cookies = {}

        # user agent
        user_agent = self._web_config.get("user_agent", "BBOT")
        if "User-Agent" not in headers:
            headers["User-Agent"] = user_agent
        kwargs["headers"] = headers
        kwargs["cookies"] = cookies
        # proxy
        proxies = self._web_config.get("http_proxy", None)
        kwargs["proxy"] = proxies

        log.verbose(f"Creating httpx.AsyncClient({args}, {kwargs})")
        super().__init__(*args, **kwargs)
        if not self._persist_cookies:
            self._cookies = DummyCookies()

    def build_request(self, *args, **kwargs):
        if args:
            url = args[0]
            kwargs["url"] = url
        url = kwargs["url"]

        target_in_scope = self._target.in_scope(str(url))

        if target_in_scope:
            if not kwargs.get("cookies", None):
                kwargs["cookies"] = {}
            for ck, cv in self._web_config.get("http_cookies", {}).items():
                if ck not in kwargs["cookies"]:
                    kwargs["cookies"][ck] = cv

        request = super().build_request(**kwargs)

        if target_in_scope:
            for hk, hv in self._web_config.get("http_headers", {}).items():
                hv = str(hv)
                # don't clobber headers
                if hk not in request.headers:
                    request.headers[hk] = hv
        return request

    def _merge_cookies(self, cookies):
        if self._persist_cookies:
            return super()._merge_cookies(cookies)
        return cookies

    @property
    def retries(self):
        return self._transport._pool._retries
