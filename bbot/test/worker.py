"""Per-worker test resources: server ports and the BBOT home directory.

Ports and the home directory are process-global, so under ``pytest -n`` each
worker needs its own: otherwise the servers collide on one port, and whichever
worker finishes first deletes the home directory out from under the rest.

Serial runs have no ``PYTEST_XDIST_WORKER`` and keep the original values.
"""

import os
from contextlib import suppress
from pathlib import Path

# Wider than the number of distinct base ports, so worker blocks cannot overlap.
WORKER_PORT_STRIDE = 100

BASE_BBOT_TEST_DIR = Path("/tmp/.bbot_test")


def worker_id():
    worker = os.environ.get("PYTEST_XDIST_WORKER", "")
    return worker if worker.startswith("gw") else ""


# BBOTLogger only configures logging when _BBOT_LOGGING_SETUP is unset, so that
# bbot subprocesses reuse the parent's setup. Workers inherit the variable and
# so skipped setup entirely, leaving debug.log empty. Clear it before bbot.core
# is imported; BBOTLogger sets it again, so this worker's subprocesses still
# inherit it.
if worker_id():
    os.environ.pop("_BBOT_LOGGING_SETUP", None)


def _worker_index():
    worker = worker_id()
    if worker:
        with suppress(ValueError):
            return int(worker[2:])
    return 0


def worker_port(base):
    return base + (_worker_index() * WORKER_PORT_STRIDE)


def worker_dir(base=BASE_BBOT_TEST_DIR):
    worker = worker_id()
    return Path(f"{base}_{worker}") if worker else Path(base)


HTTPSERVER_PORT = worker_port(8888)
HTTPSERVER_SSL_PORT = worker_port(9999)
HTTPSERVER_ALLINTERFACES_PORT = worker_port(5556)
FASTAPI_PORT = worker_port(8978)
WEBSOCKET_PORT = worker_port(8765)

# The scope-accuracy test binds distinct loopback IPs (127.0.0.77, .88, ...),
# which is still the same port on every worker, so it moves with the worker too.
# Inside the stride block, so it cannot reach the next worker's range.
HTTPSERVER_PORT_ALT = HTTPSERVER_PORT + 1

HTTPSERVER_HOSTPORT = f"127.0.0.1:{HTTPSERVER_PORT}"
HTTPSERVER_SSL_HOSTPORT = f"127.0.0.1:{HTTPSERVER_SSL_PORT}"
HTTPSERVER_URL = f"http://{HTTPSERVER_HOSTPORT}"
HTTPSERVER_SSL_URL = f"https://{HTTPSERVER_SSL_HOSTPORT}"

# Distinct from the 127.0.0.1 forms: virtualhost asserts on the Host header,
# where "localhost:8888" and "127.0.0.1:8888" are not interchangeable.
LOCALHOST_HOSTPORT = f"localhost:{HTTPSERVER_PORT}"
LOCALHOST_URL = f"http://{LOCALHOST_HOSTPORT}"
LOCALHOST_SSL_URL = f"https://localhost:{HTTPSERVER_SSL_PORT}"

FASTAPI_URL = f"http://127.0.0.1:{FASTAPI_PORT}"

BBOT_TEST_DIR = worker_dir()
# git_clone writes to git_repos/<home name>/<repo>, so tests asserting on those
# paths need the basename, not a hardcoded ".bbot_test".
BBOT_TEST_DIR_NAME = BBOT_TEST_DIR.name

# Bounded so a container that dies on startup fails fast instead of hanging the
# run until the global pytest timeout.
CONTAINER_READY_TIMEOUT = int(os.environ.get("BBOT_TEST_CONTAINER_TIMEOUT", "180"))

_OOM_HINT = "A container that exits with code 137 was OOM-killed; it competes with the other test workers for memory."


async def wait_for_container(name, connect, timeout=CONTAINER_READY_TIMEOUT):
    """Retry ``connect`` until it succeeds, or raise once ``timeout`` elapses.

    ``connect`` may be sync or async. Returns whatever it returns.
    """
    import asyncio
    import inspect
    import time

    deadline = time.time() + timeout
    while True:
        try:
            result = connect()
            return await result if inspect.isawaitable(result) else result
        except Exception as e:
            if time.time() > deadline:
                raise RuntimeError(
                    f"{name} did not become ready within {timeout}s. {_OOM_HINT} Last error: {e}"
                ) from e
            await asyncio.sleep(0.5)
