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


def _reset_logging_setup_flag():
    """Let each xdist worker set up its own logging.

    ``BBOTLogger`` only configures logging when ``_BBOT_LOGGING_SETUP`` is
    absent from the environment, so that bbot subprocesses spawned during a
    scan reuse the parent's setup instead of building a second one.

    xdist workers are forked from the pytest parent and inherit that variable,
    so every worker skipped setup: ``listener`` stayed None and nothing was
    ever written to ``debug.log``. Tests that read the scan's debug log then
    asserted against an empty file.

    Clearing it here (before ``bbot.core`` is imported) makes each worker a
    fresh logging root. ``BBOTLogger`` immediately sets the variable again, so
    subprocesses spawned by this worker still inherit it and still skip setup.
    """
    if worker_id():
        os.environ.pop("_BBOT_LOGGING_SETUP", None)


_reset_logging_setup_flag()


def worker_index():
    """This xdist worker's zero-based index, or 0 when running serially."""
    worker = worker_id()
    if worker:
        with suppress(ValueError):
            return int(worker[2:])
    return 0


def port_offset():
    """Global port shift, from ``BBOT_TEST_PORT_OFFSET``.

    Lets a second copy of the suite run alongside one that already owns the
    base ports (another checkout, a CI container, a stray leftover server).
    Without it the two collide on 8888 and the failures look like a bug in the
    worker isolation rather than two runs fighting over a socket.
    """
    with suppress(ValueError):
        return int(os.environ.get("BBOT_TEST_PORT_OFFSET", "0"))
    return 0


def worker_port(base):
    """Offset ``base`` into this worker's port block."""
    return base + (worker_index() * WORKER_PORT_STRIDE) + port_offset()


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

# Basename of the BBOT home directory (".bbot_test", or ".bbot_test_gw0" under
# xdist). Some modules embed the home directory's *name* in the paths they
# produce -- git_clone writes to ``git_repos/<home name>/<repo>`` -- so tests
# asserting on those paths need this rather than a hardcoded ".bbot_test".
BBOT_TEST_DIR_NAME = worker_dir().name

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

# The scope-accuracy test starts six more servers on distinct loopback IPs
# (127.0.0.77, .88, ...). Distinct IPs are not enough under xdist: every worker
# binds the same IP:port pairs, so these have to move with the worker too.
# Both live inside the worker's stride block, so they cannot reach the next
# worker's range.
OTHER_HTTPSERVER_PORT = HTTPSERVER_PORT
OTHER_HTTPSERVER_PORT_ALT = HTTPSERVER_PORT + 1

# How long a test waits for a docker-backed service (elasticsearch, mongo, ...)
# to accept connections before giving up. These used to spin forever, so a
# container that died on startup hung the whole run until the global pytest
# timeout fired, with no indication of what was stuck.
CONTAINER_READY_TIMEOUT = int(os.environ.get("BBOT_TEST_CONTAINER_TIMEOUT", "180"))
