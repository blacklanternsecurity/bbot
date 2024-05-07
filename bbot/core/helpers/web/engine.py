import ssl
import anyio
import httpx
import asyncio
import logging
import traceback
from socksio.exceptions import SOCKSError
from contextlib import asynccontextmanager

from .client import BBOTAsyncClient
from bbot.core.engine import EngineServer
from bbot.core.helpers.misc import bytes_to_human, human_to_bytes, get_exception_chain

log = logging.getLogger("bbot.core.helpers.web.engine")


class HTTPEngine(EngineServer):

    CMDS = {
        0: "request",
        1: "request_batch",
        2: "request_custom_batch",
        3: "download",
        99: "mock",
    }

    client_only_options = (
        "retries",
        "max_redirects",
    )

    def __init__(self, socket_path, target, config={}):
        super().__init__(socket_path)
        self.target = target
        self.config = config
        self.http_debug = self.config.get("http_debug", False)
        self._ssl_context_noverify = None
        self.ssl_verify = self.config.get("ssl_verify", False)
        if self.ssl_verify is False:
            self.ssl_verify = self.ssl_context_noverify()
        self.web_client = self.AsyncClient(persist_cookies=False)

    def AsyncClient(self, *args, **kwargs):
        kwargs["_config"] = self.config
        kwargs["_target"] = self.target
        retries = kwargs.pop("retries", self.config.get("http_retries", 1))
        kwargs["transport"] = httpx.AsyncHTTPTransport(retries=retries, verify=self.ssl_verify)
        kwargs["verify"] = self.ssl_verify
        return BBOTAsyncClient(*args, **kwargs)

    async def request(self, *args, **kwargs):
        raise_error = kwargs.pop("raise_error", False)
        # TODO: use this
        cache_for = kwargs.pop("cache_for", None)  # noqa

        client = kwargs.get("client", self.web_client)

        # allow vs follow, httpx why??
        allow_redirects = kwargs.pop("allow_redirects", None)
        if allow_redirects is not None and "follow_redirects" not in kwargs:
            kwargs["follow_redirects"] = allow_redirects

        # in case of URL only, assume GET request
        if len(args) == 1:
            kwargs["url"] = args[0]
            args = []

        url = kwargs.get("url", "")

        if not args and "method" not in kwargs:
            kwargs["method"] = "GET"

        client_kwargs = {}
        for k in list(kwargs):
            if k in self.client_only_options:
                v = kwargs.pop(k)
                client_kwargs[k] = v

        if client_kwargs:
            client = self.AsyncClient(**client_kwargs)

        async with self._acatch(url, raise_error):
            if self.http_debug:
                logstr = f"Web request: {str(args)}, {str(kwargs)}"
                self.log.trace(logstr)
            response = await client.request(*args, **kwargs)
            if self.http_debug:
                self.log.trace(
                    f"Web response from {url}: {response} (Length: {len(response.content)}) headers: {response.headers}"
                )
            return response

    async def request_batch(self, urls, *args, threads=10, **kwargs):
        tasks = {}

        def new_task(url):
            task = asyncio.create_task(self.request(url, *args, **kwargs))
            tasks[task] = url

        urls = list(urls)
        for _ in range(threads):  # Start initial batch of tasks
            if urls:  # Ensure there are args to process
                new_task(urls.pop(0))

        while tasks:  # While there are tasks pending
            # Wait for the first task to complete
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

            for task in done:
                results = task.result()
                url = tasks.pop(task)

                if results:
                    yield (url, results)

                if urls:  # Start a new task for each one completed, if URLs remain
                    new_task(urls.pop(0))

    async def download(self, url, **kwargs):
        follow_redirects = kwargs.pop("follow_redirects", True)
        filename = kwargs.pop("filename")
        max_size = kwargs.pop("max_size", None)
        warn = kwargs.pop("warn", True)
        raise_error = kwargs.pop("raise_error", False)
        if max_size is not None:
            max_size = human_to_bytes(max_size)
        kwargs["follow_redirects"] = follow_redirects
        if not "method" in kwargs:
            kwargs["method"] = "GET"
        try:
            total_size = 0
            chunk_size = 8192

            async with self._acatch(url, raise_error=True), self.web_client.stream(url=url, **kwargs) as response:
                status_code = getattr(response, "status_code", 0)
                self.log.debug(f"Download result: HTTP {status_code}")
                if status_code != 0:
                    response.raise_for_status()
                    with open(filename, "wb") as f:
                        agen = response.aiter_bytes(chunk_size=chunk_size)
                        async for chunk in agen:
                            if max_size is not None and total_size + chunk_size > max_size:
                                self.log.verbose(
                                    f"Filesize of {url} exceeds {bytes_to_human(max_size)}, file will be truncated"
                                )
                                agen.aclose()
                                break
                            total_size += chunk_size
                            f.write(chunk)
                    return True
        except httpx.HTTPError as e:
            log_fn = self.log.verbose
            if warn:
                log_fn = self.log.warning
            log_fn(f"Failed to download {url}: {e}")
            if raise_error:
                raise

    def ssl_context_noverify(self):
        if self._ssl_context_noverify is None:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            ssl_context.options &= ~ssl.OP_NO_SSLv2 & ~ssl.OP_NO_SSLv3
            ssl_context.set_ciphers("ALL:@SECLEVEL=0")
            ssl_context.options |= 0x4  # Add the OP_LEGACY_SERVER_CONNECT option
            self._ssl_context_noverify = ssl_context
        return self._ssl_context_noverify

    @asynccontextmanager
    async def _acatch(self, url, raise_error):
        """
        Asynchronous context manager to handle various httpx errors during a request.

        Yields:
            None

        Note:
            This function is internal and should generally not be used directly.
            `url`, `args`, `kwargs`, and `raise_error` should be in the same context as this function.
        """
        try:
            yield
        except httpx.TimeoutException:
            if raise_error:
                raise
            else:
                log.verbose(f"HTTP timeout to URL: {url}")
        except httpx.ConnectError:
            if raise_error:
                raise
            else:
                log.debug(f"HTTP connect failed to URL: {url}")
        except httpx.HTTPError as e:
            if raise_error:
                raise
            else:
                log.trace(f"Error with request to URL: {url}: {e}")
                log.trace(traceback.format_exc())
        except ssl.SSLError as e:
            msg = f"SSL error with request to URL: {url}: {e}"
            if raise_error:
                raise httpx.RequestError(msg)
            else:
                log.trace(msg)
                log.trace(traceback.format_exc())
        except anyio.EndOfStream as e:
            msg = f"AnyIO error with request to URL: {url}: {e}"
            if raise_error:
                raise httpx.RequestError(msg)
            else:
                log.trace(msg)
                log.trace(traceback.format_exc())
        except SOCKSError as e:
            msg = f"SOCKS error with request to URL: {url}: {e}"
            if raise_error:
                raise httpx.RequestError(msg)
            else:
                log.trace(msg)
                log.trace(traceback.format_exc())
        except BaseException as e:
            # don't log if the error is the result of an intentional cancellation
            if not any(isinstance(_e, asyncio.exceptions.CancelledError) for _e in get_exception_chain(e)):
                log.trace(f"Unhandled exception with request to URL: {url}: {e}")
                log.trace(traceback.format_exc())
            raise

    def mock(self, *args, **kwargs):
        import pytest
        from bbot.core.helpers.interactsh import server_list as interactsh_servers

        @pytest.fixture
        def non_mocked_hosts() -> list:
            return ["127.0.0.1", "localhost", "raw.githubusercontent.com"] + interactsh_servers
