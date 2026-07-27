"""Test server ports, offset per xdist worker.

The test suite starts local HTTP servers (``bbot_httpserver``,
``bbot_httpserver_ssl``, ``bbot_httpserver_allinterfaces``) and points scans at
them. Under ``pytest -n``, every worker runs its own copy of those fixtures. If
they all bound the same port, all but one worker would die with EADDRINUSE, so
each worker gets its own block of ports.

This lives outside ``conftest.py`` so test modules can import the resolved ports
without pulling in conftest's import-time side effects (env vars, logger
surgery).

Serial runs have no ``PYTEST_XDIST_WORKER`` set and keep the original ports, so
nothing changes when running ``pytest`` without ``-n``.
"""

import os
from contextlib import suppress

# Port block per worker. Wider than the number of distinct base ports, so
# worker N's block can never overlap worker N+1's.
WORKER_PORT_STRIDE = 100

BASE_HTTPSERVER_PORT = 8888
BASE_HTTPSERVER_SSL_PORT = 9999
BASE_HTTPSERVER_ALLINTERFACES_PORT = 5556


def worker_index():
    """This xdist worker's zero-based index, or 0 when running serially."""
    worker = os.environ.get("PYTEST_XDIST_WORKER", "")
    if worker.startswith("gw"):
        with suppress(ValueError):
            return int(worker[2:])
    return 0


def worker_port(base):
    """Offset ``base`` into this worker's port block."""
    return base + (worker_index() * WORKER_PORT_STRIDE)


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
