import ssl
import anyio
import httpx
import asyncio
import logging
import traceback
from socksio.exceptions import SOCKSError
from contextlib import asynccontextmanager

from bbot.core.engine import EngineServer
from bbot.core.helpers.misc import bytes_to_human, human_to_bytes, get_exception_chain

log = logging.getLogger("bbot.core.helpers.web.engine")


class HTTPEngine(EngineServer):

    CMDS = {
        0: "request",
        1: "request_batch",
        2: "request_custom_batch",
        3: "download",
    }

    client_only_options = (
        "retries",
        "max_redirects",
    )

    def __init__(self, socket_path, target, config={}, debug=False):
        super().__init__(socket_path, debug=debug)
        self.target = target
        self.config = config
        self.web_config = self.config.get("web", {})
        self.http_debug = self.web_config.get("debug", False)
        self._ssl_context_noverify = None
        self.web_clients = {}
        self.web_clients[0] = self.AsyncClient(persist_cookies=False, retries=0)
        self.web_client = self.web_clients[0]

    def AsyncClient(self, *args, **kwargs):
        # cache by retries to prevent unwanted accumulation of clients
        # (they are not garbage-collected)
        retries = kwargs.get("retries", 0)
        try:
            return self.web_clients[retries]
        except KeyError:
            from .client import BBOTAsyncClient

            client = BBOTAsyncClient.from_config(self.config, self.target, *args, **kwargs)
            self.web_clients[retries] = client
            return client

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
                log.trace(logstr)
            response = await client.request(*args, **kwargs)
            if self.http_debug:
                log.trace(
                    f"Web response from {url}: {response} (Length: {len(response.content)}) headers: {response.headers}"
                )
            return response

    async def request_batch(self, urls, *args, threads=10, **kwargs):
        tasks = {}
        client_id = self.client_id_var.get()

        urls = list(urls)

        def new_task():
            if urls:
                url = urls.pop(0)
                task = self.new_child_task(client_id, self.request(url, *args, **kwargs))
                tasks[task] = url

        for _ in range(threads):  # Start initial batch of tasks
            new_task()

        while tasks:  # While there are tasks pending
            # Wait for the first task to complete
            finished = await self.finished_tasks(client_id, timeout=120)

            for task in finished:
                response = task.result()
                url = tasks.pop(task)
                yield (url, response)
                new_task()

    async def request_custom_batch(self, urls_and_kwargs, threads=10):
        tasks = {}
        client_id = self.client_id_var.get()
        urls_and_kwargs = list(urls_and_kwargs)

        def new_task():
            if urls_and_kwargs:  # Ensure there are args to process
                url, kwargs, custom_tracker = urls_and_kwargs.pop(0)
                task = self.new_child_task(client_id, self.request(url, **kwargs))
                tasks[task] = (url, kwargs, custom_tracker)

        for _ in range(threads):  # Start initial batch of tasks
            new_task()

        while tasks:  # While there are tasks pending
            # Wait for the first task to complete
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

            for task in done:
                response = task.result()
                url, kwargs, custom_tracker = tasks.pop(task)
                yield (url, kwargs, custom_tracker, response)
                new_task()

    async def download(self, url, **kwargs):
        warn = kwargs.pop("warn", True)
        filename = kwargs.pop("filename")
        raise_error = kwargs.get("raise_error", False)
        try:
            result = await self.stream_request(url, **kwargs)
            if result is None:
                raise httpx.HTTPError(f"No response from {url}")
            content, response = result
            log.debug(f"Download result: HTTP {response.status_code}")
            response.raise_for_status()
            with open(filename, "wb") as f:
                f.write(content)
            return filename
        except httpx.HTTPError as e:
            log_fn = log.verbose
            if warn:
                log_fn = log.warning
            log_fn(f"Failed to download {url}: {e}")
            if raise_error:
                raise

    async def stream_request(self, url, **kwargs):
        follow_redirects = kwargs.pop("follow_redirects", True)
        max_size = kwargs.pop("max_size", None)
        raise_error = kwargs.pop("raise_error", False)
        if max_size is not None:
            max_size = human_to_bytes(max_size)
        kwargs["follow_redirects"] = follow_redirects
        if not "method" in kwargs:
            kwargs["method"] = "GET"
        try:
            total_size = 0
            chunk_size = 8192
            chunks = []

            async with self._acatch(url, raise_error=True), self.web_client.stream(url=url, **kwargs) as response:
                agen = response.aiter_bytes(chunk_size=chunk_size)
                async for chunk in agen:
                    _chunk_size = len(chunk)
                    if max_size is not None and total_size + _chunk_size > max_size:
                        log.verbose(
                            f"Size of response from {url} exceeds {bytes_to_human(max_size)}, file will be truncated"
                        )
                        agen.aclose()
                        break
                    total_size += _chunk_size
                    chunks.append(chunk)
                return b"".join(chunks), response
        except httpx.HTTPError as e:
            self.log.debug(f"Error requesting {url}: {e}")
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
