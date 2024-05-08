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

    def __init__(self, *args, **kwargs):
        self._config = kwargs.pop("_config")
        self._target = kwargs.pop("_target")

        http_debug = self._config.get("http_debug", None)
        if http_debug:
            log.trace(f"Creating AsyncClient: {args}, {kwargs}")

        self._persist_cookies = kwargs.pop("persist_cookies", True)

        # timeout
        http_timeout = self._config.get("http_timeout", 20)
        if not "timeout" in kwargs:
            kwargs["timeout"] = http_timeout

        # headers
        headers = kwargs.get("headers", None)
        if headers is None:
            headers = {}
        # user agent
        user_agent = self._config.get("user_agent", "BBOT")
        if "User-Agent" not in headers:
            headers["User-Agent"] = user_agent
        kwargs["headers"] = headers
        # proxy
        proxies = self._config.get("http_proxy", None)
        kwargs["proxies"] = proxies

        super().__init__(*args, **kwargs)
        if not self._persist_cookies:
            self._cookies = DummyCookies()

    def build_request(self, *args, **kwargs):
        request = super().build_request(*args, **kwargs)
        # add custom headers if the URL is in-scope
        # TODO: re-enable this
        if self._target.in_scope(str(request.url)):
            for hk, hv in self._config.get("http_headers", {}).items():
                # don't clobber headers
                if hk not in request.headers:
                    request.headers[hk] = hv
        return request

    def _merge_cookies(self, cookies):
        if self._persist_cookies:
            return super()._merge_cookies(cookies)
        return cookies
