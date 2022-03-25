import logging
import requests
from time import sleep
from requests.exceptions import RequestException

log = logging.getLogger("bbot.core.helpers.web")


def request(self, *args, **kwargs):
    """
    Multipurpose function for making web requests
    """

    http_timeout = self.config.get("http_timeout", 10)
    user_agent = self.config.get(
        "user_agent",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1",
    )
    ssl_verify = self.config.get("ssl_verify", True)

    # in case of URL only, assume GET request
    if len(args) == 1:
        kwargs["url"] = args[0]
        args = []

    url = kwargs.get("url", "")
    retries = kwargs.pop("retries", 0)
    session = kwargs.pop("session", None)

    if not args and "method" not in kwargs:
        kwargs["method"] = "GET"

    if not "timeout" in kwargs:
        kwargs["timeout"] = http_timeout

    headers = kwargs.get("headers", {})

    if "User-Agent" not in headers:
        headers.update({"User-Agent": user_agent})
    kwargs["headers"] = headers

    if not "verify" in kwargs:
        kwargs["verify"] = ssl_verify

    while retries == "infinite" or retries >= 0:
        try:
            logstr = f"Web request: {str(args)}, {str(kwargs)}"
            log.debug(logstr)
            if session is not None:
                response = session.request(*args, **kwargs)
            else:
                response = requests.request(*args, **kwargs)
            log.debug(
                f"Web response: {response} (Length: {len(response.content)}) headers: {response.headers}"
            )
            return response
        except RequestException as e:
            log.debug(f"Web error: {e}")
            if retries != "infinite":
                retries -= 1
            if retries == "infinite" or retries >= 0:
                log.warning(f'Error requesting "{url}", retrying...')
                sleep(2)
            else:
                return e
