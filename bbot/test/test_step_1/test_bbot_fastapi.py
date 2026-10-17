import time
import json
import multiprocessing
from pathlib import Path
from subprocess import Popen
from contextlib import suppress
from urllib.request import urlopen, Request
from urllib.error import URLError
from urllib.parse import urlencode
from bbot.test.worker import FASTAPI_PORT, FASTAPI_URL, HTTPSERVER_URL

cwd = Path(__file__).parent.parent.parent


def run_bbot_multiprocess(queue):
    from bbot.scanner import Scanner

    scan = Scanner(HTTPSERVER_URL, "blacklanternsecurity.com", modules=["http"])
    events = [e.json() for e in scan.start()]
    queue.put(events)


def test_bbot_multiprocess(bbot_httpserver):
    bbot_httpserver.expect_request("/").respond_with_data("test@blacklanternsecurity.com")

    queue = multiprocessing.Queue()
    events_process = multiprocessing.Process(target=run_bbot_multiprocess, args=(queue,))
    events_process.start()
    events_process.join(timeout=300)
    events = queue.get(timeout=10)
    assert len(events) >= 3
    scan_events = [e for e in events if e["type"] == "SCAN"]
    assert len(scan_events) == 2
    assert any(e.get("data", "") == "test@blacklanternsecurity.com" for e in events)


def test_bbot_fastapi(bbot_httpserver):
    bbot_httpserver.expect_request("/").respond_with_data("test@blacklanternsecurity.com")
    fastapi_process = start_fastapi_server()

    try:
        # wait for the server to start with a timeout of 60 seconds
        start_time = time.time()
        while True:
            try:
                response = urlopen(f"{FASTAPI_URL}/ping")
                response.read()
                break
            except (URLError, ConnectionError):
                if time.time() - start_time > 60:
                    raise TimeoutError("Server did not start within 60 seconds.")
                time.sleep(0.1)
                continue

        # run a scan
        params = urlencode({"targets": [HTTPSERVER_URL, "blacklanternsecurity.com"]}, doseq=True)
        req = Request(f"{FASTAPI_URL}/start?{params}")
        response = urlopen(req, timeout=100)
        events = json.loads(response.read())
        assert len(events) >= 3
        scan_events = [e for e in events if e["type"] == "SCAN"]
        assert len(scan_events) == 2
        assert any(e.get("data", "") == "test@blacklanternsecurity.com" for e in events)

    finally:
        with suppress(Exception):
            fastapi_process.terminate()


def start_fastapi_server():
    import os
    import sys

    env = os.environ.copy()
    with suppress(KeyError):
        del env["BBOT_TESTING"]
    python_executable = str(sys.executable)
    process = Popen(
        [python_executable, "-m", "uvicorn", "bbot.test.fastapi_test:app", "--port", str(FASTAPI_PORT)],
        cwd=cwd,
        env=env,
    )
    return process
