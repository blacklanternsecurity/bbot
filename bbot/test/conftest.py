import os
import ssl
import time
import yaml
import pytest
import shutil
import asyncio
import logging
from pathlib import Path
from contextlib import suppress
from pytest_httpserver import HTTPServer

from bbot.test.worker import (
    BBOT_TEST_DIR,
    HTTPSERVER_ALLINTERFACES_PORT,
    HTTPSERVER_PORT,
    HTTPSERVER_SSL_PORT,
)

from bbot.core import CORE
from bbot.core.helpers.misc import execute_sync_or_async
from bbot.core.helpers.interactsh import server_list as interactsh_servers

# silence stdout + trace
root_logger = logging.getLogger()
pytest_debug_file = Path(__file__).parent.parent.parent / "pytest_debug.log"
debug_handler = logging.FileHandler(pytest_debug_file)
debug_handler.setLevel(logging.DEBUG)
debug_format = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s %(filename)s:%(lineno)s %(message)s")
debug_handler.setFormatter(debug_format)
root_logger.addHandler(debug_handler)

with open(Path(__file__).parent / "test.conf") as _f:
    test_config = yaml.safe_load(_f) or {}

# Give each xdist worker its own BBOT home. test.conf carries the serial default;
# under -n the workers would otherwise share caches, scan output and temp files,
# and the sessionfinish cleanup below would delete a directory still in use.
test_config["home"] = str(BBOT_TEST_DIR)

os.environ["BBOT_DEBUG"] = "True"
CORE.logger.log_level = logging.DEBUG

# silence all stderr output:
stderr_handler = CORE.logger.log_handlers["stderr"]
stderr_handler.setLevel(logging.CRITICAL)
# worker.py clears _BBOT_LOGGING_SETUP for xdist workers, so every process that
# reaches here (serial or worker) owns a real QueueListener. If it is missing,
# logging never got set up and debug.log would silently stay empty, so fail
# loudly instead of continuing with logging quietly broken.
if CORE.logger.listener is None:
    raise RuntimeError(
        "BBOT logging was not initialized in this process "
        f"(PYTEST_XDIST_WORKER={os.environ.get('PYTEST_XDIST_WORKER', '')!r}). "
        "debug.log would be empty and log-reading tests would fail with "
        "confusing assertion errors."
    )
handlers = list(CORE.logger.listener.handlers)
handlers.remove(stderr_handler)
CORE.logger.listener.handlers = tuple(handlers)

for h in root_logger.handlers:
    h.addFilter(lambda x: x.levelname not in ("STDOUT", "TRACE"))


CORE.merge_default(test_config)


@pytest.fixture(autouse=True)
def silence_live_logging():
    for handler in logging.getLogger().handlers:
        if type(handler).__name__ == "_LiveLoggingStreamHandler":
            handler.setLevel(logging.CRITICAL)


def _patch_python_module_loader():
    """Restore the standard ``_module_consumers`` bump on the ``python`` output
    module for every test scan.

    In production, ``python._increment_consumer_count`` is a no-op (its
    ``_worker`` is also no-op — see ``bbot/modules/output/python.py``),
    so events flowing through ``async_start`` don't pin themselves and
    ``_minimize()`` correctly strips heavy fields when their pipeline
    finishes. But module + integration tests routinely do
    ``events = [e async for e in scan.async_start()]`` and assert on
    ``event.tags`` / ``event.resolved_hosts`` / ``event.body`` / etc.
    *after* the scan completes — so for tests we want the standard
    increment to fire, which keeps events pinned through assertion time.

    BBOT's ``ModuleLoader.load_module`` exec's a fresh module spec each
    call, so each Scanner gets a brand-new ``python`` *class object*,
    not the one we'd see by importing ``bbot.modules.output.python``
    statically. Patching the imported class therefore has no effect.
    Instead we wrap the loader: every time a fresh ``python`` class is
    materialized, restore the increment on it.
    """
    from bbot.core.modules import ModuleLoader
    from bbot.modules.base import BaseModule

    orig = ModuleLoader.load_module

    def patched(self, module_name):
        cls = orig(self, module_name)
        if module_name == "python":
            cls._increment_consumer_count = BaseModule._increment_consumer_count
        return cls

    ModuleLoader.load_module = patched


_patch_python_module_loader()


def stop_server(server):
    server.stop()
    while server.is_running():
        time.sleep(0.1)  # Wait a bit before checking again


@pytest.fixture
def bbot_httpserver():
    server = HTTPServer(host="127.0.0.1", port=HTTPSERVER_PORT, threaded=True)
    server.start()

    yield server

    server.clear()
    stop_server(server)  # Ensure the server is fully stopped

    server.check_assertions()
    server.clear()


@pytest.fixture
def bbot_httpserver_ssl():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    current_dir = Path(__file__).parent
    keyfile = str(current_dir / "testsslkey.pem")
    certfile = str(current_dir / "testsslcert.pem")
    context.load_cert_chain(certfile, keyfile)
    server = HTTPServer(host="127.0.0.1", port=HTTPSERVER_SSL_PORT, ssl_context=context, threaded=True)
    server.start()

    yield server

    server.clear()
    stop_server(server)  # Ensure the server is fully stopped

    server.check_assertions()
    server.clear()


def _should_mock(host):
    """Check if a request to this host should be mocked (True = mock, False = pass through)."""
    return host not in ["127.0.0.1", "localhost", "raw.githubusercontent.com"] + interactsh_servers


@pytest.fixture
def blasthttp_mock():
    """
    Mock fixture for blasthttp engine requests.

    Patches HTTPEngine.request() to intercept external requests and return
    mock responses. Requests to localhost/127.0.0.1 pass through to real blasthttp.
    """
    from bbot.core.helpers.web.web import WebHelper
    from bbot.test.mock_blasthttp import BlasthttpMock

    mock = BlasthttpMock(should_mock_fn=_should_mock)
    original_request = WebHelper.request

    async def patched_request(self, *args, **kwargs):
        # Peek at URL without modifying kwargs
        url = kwargs.get("url", "")
        if not url and args:
            url = str(args[0])
        # If resolve_ip points to localhost, pass through to real blasthttp
        resolve_ip = kwargs.get("resolve_ip", "")
        if resolve_ip and resolve_ip in ("127.0.0.1", "::1"):
            return await original_request(self, *args, **kwargs)
        if url and mock.should_intercept(url):
            # Read raise_error before the mock pops it
            raise_error = kwargs.get("raise_error", False)
            result = await mock.handle_engine_request(self, *args, **kwargs)
            # Convert engine-style error dicts to WebError exceptions
            if isinstance(result, dict) and "_request_error" in result:
                if raise_error:
                    from bbot.errors import WebError

                    error = WebError(result["_request_error"])
                    error.response = result.get("_response")
                    raise error
                return None
            return result
        return await original_request(self, *args, **kwargs)

    original_request_batch_stream = WebHelper.request_batch_stream

    async def patched_request_batch_stream(self, urls, threads=10, **kwargs):
        import blasthttp
        from collections import deque

        # Run the real entry-parsing and config-building logic unmodified
        entries = []
        has_tracker = False
        for entry in urls:
            if isinstance(entry, str):
                entries.append((entry, kwargs, None))
            elif isinstance(entry, tuple):
                url = entry[0]
                req_kwargs = entry[1] if len(entry) > 1 and isinstance(entry[1], dict) else kwargs
                tracker = entry[2] if len(entry) > 2 else None
                if tracker is not None:
                    has_tracker = True
                entries.append((url, req_kwargs, tracker))
            else:
                entries.append((str(entry), kwargs, None))

        if not entries:
            return

        configs = []
        trackers_by_url = {}
        for url, req_kwargs, tracker in entries:
            url, method, blast_kwargs = self._build_blasthttp_kwargs(url, **req_kwargs)
            config = blasthttp.BatchConfig(url, **blast_kwargs)
            configs.append(config)
            trackers_by_url.setdefault(config.url, deque()).append(tracker)

        async for br in mock.handle_batch_stream(self.client, configs, concurrency=threads):
            response = br.response  # blasthttp.Response or None
            if has_tracker:
                queue = trackers_by_url.get(br.url)
                tracker = queue.popleft() if queue else None
                yield br.url, response, tracker
            else:
                yield br.url, response

    WebHelper.request = patched_request
    WebHelper.request_batch_stream = patched_request_batch_stream
    yield mock
    WebHelper.request = original_request
    WebHelper.request_batch_stream = original_request_batch_stream


@pytest.fixture
def bbot_httpserver_allinterfaces():
    server = HTTPServer(host="0.0.0.0", port=HTTPSERVER_ALLINTERFACES_PORT, threaded=True)
    server.start()

    yield server

    server.clear()
    if server.is_running():
        server.stop()
    server.check_assertions()
    server.clear()


class Interactsh_mock:
    def __init__(self, name):
        self.name = name
        self.log = logging.getLogger(f"bbot.interactsh.{self.name}")
        self.interactions = asyncio.Queue()  # Use an asyncio queue for async access
        self.correlation_id = "deadbeef-dead-beef-dead-beefdeadbeef"
        self.stop = False
        self.poll_task = None

    def mock_interaction(self, subdomain_tag, msg=None):
        self.log.info(f"Mocking interaction to subdomain tag: {subdomain_tag}")
        if msg is not None:
            self.log.info(msg)
        self.interactions.put_nowait(subdomain_tag)  # Add to the thread-safe queue

    async def register(self, callback=None):
        if callable(callback):
            self.poll_task = asyncio.create_task(self.poll_loop(callback))
        return "fakedomain.fakeinteractsh.com"

    async def deregister(self, callback=None):
        await asyncio.sleep(1)
        self.stop = True
        if self.poll_task is not None:
            self.poll_task.cancel()
            with suppress(asyncio.CancelledError):
                await self.poll_task

    async def poll_loop(self, callback=None):
        while not self.stop:
            data_list = await self.poll(callback)
            if not data_list:
                await asyncio.sleep(0.5)
                continue
        await asyncio.sleep(1)
        await self.poll(callback)

    async def poll(self, callback=None):
        poll_results = []
        while not self.interactions.empty():
            subdomain_tag = await self.interactions.get()  # Get the first element from the asyncio queue
            for protocol in ["HTTP", "DNS"]:
                result = {"full-id": f"{subdomain_tag}.fakedomain.fakeinteractsh.com", "protocol": protocol}
                poll_results.append(result)
                if callback is not None:
                    await execute_sync_or_async(callback, result)
            await asyncio.sleep(0.1)
        return poll_results


import threading
import http.server
import socketserver
import urllib.request


class Proxy(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "Proxy"
    urls = []

    def do_GET(self):
        self.urls.append(self.path)

        # Extract host and port from path
        netloc = urllib.parse.urlparse(self.path).netloc
        host, _, port = netloc.partition(":")

        # Fetch the content
        conn = http.client.HTTPConnection(host, port if port else 80)
        conn.request("GET", self.path, headers=self.headers)
        response = conn.getresponse()

        # Send the response back to the client
        self.send_response(response.status)
        for header, value in response.getheaders():
            self.send_header(header, value)
        self.end_headers()
        self.copyfile(response, self.wfile)

        response.close()
        conn.close()


@pytest.fixture
def proxy_server():
    # Set up an HTTP server that acts as a simple proxy.
    server = socketserver.ThreadingTCPServer(("localhost", 0), Proxy)

    # Start the server in a new thread.
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    yield server

    # Stop the server.
    server.shutdown()
    server_thread.join()


def pytest_collection_modifyitems(config, items):
    """Pin docker-backed tests to one xdist worker.

    They start real containers with fixed names and fixed host port bindings
    (kafka, elastic, mongo, mysql, nats, postgres, rabbitmq), so two workers
    running them at once fight over both. They already mark themselves with
    ``skip_distro_tests``, so reuse that as the signal.
    """
    for item in items:
        cls = getattr(item, "cls", None)
        if cls is not None and getattr(cls, "skip_distro_tests", False):
            item.add_marker(pytest.mark.xdist_group("docker"))


def pytest_terminal_summary(terminalreporter, exitstatus, config):  # pragma: no cover
    RED = "\033[1;31m"
    GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[1;34m"
    CYAN = "\033[1;36m"
    RESET = "\033[0m"
    stats = terminalreporter.stats
    total_tests = len(terminalreporter._session.items)
    passed = len(stats.get("passed", []))
    skipped = len(stats.get("skipped", []))
    errors = len(stats.get("error", []))
    failed = stats.get("failed", [])

    terminalreporter.write("\nTest Session Summary:")
    terminalreporter.write(f"\nTotal tests run: {total_tests}")
    terminalreporter.write(
        f"\n{GREEN}Passed: {passed}{RESET}, {RED}Failed: {len(failed)}{RESET}, {YELLOW}Skipped: {skipped}{RESET}, Errors: {errors}"
    )

    if failed:
        terminalreporter.write(f"\n{RED}Detailed failed test report:{RESET}")
        for item in failed:
            test_name = item.nodeid.split("::")[-1] if "::" in item.nodeid else item.nodeid
            file_and_line = f"{item.location[0]}:{item.location[1]}"  # File path and line number
            terminalreporter.write(f"\n{BLUE}Test Name: {test_name}{RESET} {CYAN}({file_and_line}){RESET}")
            terminalreporter.write(f"\n{RED}Location: {item.nodeid} at {item.location[0]}:{item.location[1]}{RESET}")
            terminalreporter.write(f"\n{RED}Failure details:\n{item.longreprtext}{RESET}")


# BELOW: debugging for frozen/hung tests
import psutil
import traceback
import inspect


def _print_detailed_info():  # pragma: no cover
    """
    Debugging pytests hanging
    """
    print("=== Detailed Thread and Process Information ===\n")
    try:
        print("=== Threads ===")
        for thread in threading.enumerate():
            print(f"Thread Name: {thread.name}")
            print(f"Thread ID: {thread.ident}")
            print(f"Is Alive: {thread.is_alive()}")
            print(f"Daemon: {thread.daemon}")

            if hasattr(thread, "_target"):
                target = thread._target
                if target:
                    qualname = (
                        f"{target.__module__}.{target.__qualname__}"
                        if hasattr(target, "__qualname__")
                        else str(target)
                    )
                    print(f"Target Function: {qualname}")

                    if hasattr(thread, "_args"):
                        args = thread._args
                        kwargs = thread._kwargs if hasattr(thread, "_kwargs") else {}
                        arg_spec = inspect.getfullargspec(target)

                        all_args = list(args) + [f"{k}={v}" for k, v in kwargs.items()]

                        if inspect.ismethod(target) and arg_spec.args[0] == "self":
                            arg_spec.args.pop(0)

                        named_args = list(zip(arg_spec.args, all_args))
                        if arg_spec.varargs:
                            named_args.extend((f"*{arg_spec.varargs}", arg) for arg in all_args[len(arg_spec.args) :])

                        print("Arguments:")
                        for name, value in named_args:
                            print(f"  {name}: {value}")
                else:
                    print("Target Function: None")
            else:
                print("Target Function: Unknown")

            print()

        print("=== Processes ===")
        current_process = psutil.Process()
        for child in current_process.children(recursive=True):
            print(f"Process ID: {child.pid}")
            print(f"Name: {child.name()}")
            print(f"Status: {child.status()}")
            print(f"CPU Times: {child.cpu_times()}")
            print(f"Memory Info: {child.memory_info()}")
            print()

        print("=== Current Process ===")
        print(f"Process ID: {current_process.pid}")
        print(f"Name: {current_process.name()}")
        print(f"Status: {current_process.status()}")
        print(f"CPU Times: {current_process.cpu_times()}")
        print(f"Memory Info: {current_process.memory_info()}")
        print()

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        print("Traceback:")
        traceback.print_exc()


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_sessionfinish(session, exitstatus):
    # Remove handlers from all loggers to prevent logging errors at exit
    loggers = [logging.getLogger("bbot")] + list(logging.Logger.manager.loggerDict.values())
    for logger in loggers:
        handlers = getattr(logger, "handlers", [])
        for handler in handlers:
            logger.removeHandler(handler)

    # Kill any orphaned ProcessPoolExecutor workers that could block exit
    import multiprocessing

    for child in multiprocessing.active_children():
        if child.is_alive():
            child.terminate()
            child.join(timeout=5)
            if child.is_alive():
                child.kill()

    # Wipe out BBOT home dir. Scoped to this worker: under xdist the first
    # worker to finish would otherwise delete the directory out from under
    # every worker still running.
    shutil.rmtree(BBOT_TEST_DIR, ignore_errors=True)

    # Ensure stdout/stderr are blocking before pytest writes summaries
    try:
        import sys
        import fcntl
        import os
        import io

        fds = []
        for stream in (sys.stdout, sys.stderr):
            try:
                fds.append(stream.fileno())
            except io.UnsupportedOperation:
                pass
        for fd in fds:
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
    except Exception:
        pass

    yield

    # temporarily suspend stdout capture and print detailed thread info
    capmanager = session.config.pluginmanager.get_plugin("capturemanager")
    if capmanager:
        capmanager.suspend_global_capture(in_=True)

    _print_detailed_info()

    if capmanager:
        capmanager.resume_global_capture()
