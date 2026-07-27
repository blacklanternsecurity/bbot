"""Per-worker test resources: server ports and the BBOT home directory.

The test suite starts local HTTP servers and points scans at them, and it uses a
single BBOT home directory for caches, scan output and temp files. Both are
process-global, so running the suite under ``pytest -n`` needs each worker to
get its own copy:

* Ports, because every worker runs its own copy of the ``bbot_httpserver``
  fixtures, and they would otherwise all bind the same port and all but one
  would die with EADDRINUSE.
* The home directory, because ``pytest_sessionfinish`` deletes it. Whichever
  worker finished first would wipe the directory out from under every worker
  still running.

This lives outside ``conftest.py`` so test modules can import these values
without pulling in conftest's import-time side effects (env vars, logger
surgery).

Serial runs have no ``PYTEST_XDIST_WORKER`` set and keep the original ports and
home directory, so nothing changes when running ``pytest`` without ``-n``.
"""

import os
from contextlib import suppress
from pathlib import Path

# Port block per worker. Wider than the number of distinct base ports, so
# worker N's block can never overlap worker N+1's.
WORKER_PORT_STRIDE = 100

BASE_HTTPSERVER_PORT = 8888
BASE_HTTPSERVER_SSL_PORT = 9999
BASE_HTTPSERVER_ALLINTERFACES_PORT = 5556
BASE_FASTAPI_PORT = 8978
BASE_WEBSOCKET_PORT = 8765

BASE_BBOT_TEST_DIR = Path("/tmp/.bbot_test")


def worker_id():
    """This xdist worker's id (``gw0``, ``gw1``, ...), or "" when serial."""
    worker = os.environ.get("PYTEST_XDIST_WORKER", "")
    return worker if worker.startswith("gw") else ""


def worker_index():
    """This xdist worker's zero-based index, or 0 when running serially."""
    worker = worker_id()
    if worker:
        with suppress(ValueError):
            return int(worker[2:])
    return 0


def worker_port(base):
    """Offset ``base`` into this worker's port block."""
    return base + (worker_index() * WORKER_PORT_STRIDE)


def worker_dir(base=BASE_BBOT_TEST_DIR):
    """The BBOT home directory for this worker.

    Serial runs get the original path so existing behavior and any external
    tooling that looks at /tmp/.bbot_test keep working.
    """
    worker = worker_id()
    return Path(f"{base}_{worker}") if worker else Path(base)


HTTPSERVER_PORT = worker_port(BASE_HTTPSERVER_PORT)
HTTPSERVER_SSL_PORT = worker_port(BASE_HTTPSERVER_SSL_PORT)
HTTPSERVER_ALLINTERFACES_PORT = worker_port(BASE_HTTPSERVER_ALLINTERFACES_PORT)

# Host:port pairs, for tests that build their own URLs.
HTTPSERVER_HOSTPORT = f"127.0.0.1:{HTTPSERVER_PORT}"
HTTPSERVER_SSL_HOSTPORT = f"127.0.0.1:{HTTPSERVER_SSL_PORT}"

# "localhost" spellings. Kept distinct from the 127.0.0.1 forms because some
# tests (virtualhost, in particular) assert on the Host header, where
# "localhost:8888" and "127.0.0.1:8888" are not interchangeable.
LOCALHOST_HOSTPORT = f"localhost:{HTTPSERVER_PORT}"
LOCALHOST_SSL_HOSTPORT = f"localhost:{HTTPSERVER_SSL_PORT}"

# Full base URLs, the common case.
HTTPSERVER_URL = f"http://{HTTPSERVER_HOSTPORT}"
HTTPSERVER_SSL_URL = f"https://{HTTPSERVER_SSL_HOSTPORT}"
LOCALHOST_URL = f"http://{LOCALHOST_HOSTPORT}"
LOCALHOST_SSL_URL = f"https://{LOCALHOST_SSL_HOSTPORT}"

# BBOT home for this worker. Also written into the test config as `home`.
BBOT_TEST_DIR = worker_dir()

# uvicorn instance started by the fastapi test.
FASTAPI_PORT = worker_port(BASE_FASTAPI_PORT)
FASTAPI_URL = f"http://127.0.0.1:{FASTAPI_PORT}"

# websockets server started by the websocket module test.
WEBSOCKET_PORT = worker_port(BASE_WEBSOCKET_PORT)
