import time
import httpx
import multiprocessing
from pathlib import Path
from subprocess import Popen
from contextlib import suppress

cwd = Path(__file__).parent.parent.parent


def run_bbot_multiprocess(queue):
    from bbot import Scanner

    scan = Scanner("http://127.0.0.1:8888", "blacklanternsecurity.com", modules=["httpx"])
    events = [e.json() for e in scan.start()]
    queue.put(events)


def test_bbot_multiprocess(bbot_httpserver):
    bbot_httpserver.expect_request("/").respond_with_data("test@blacklanternsecurity.com")

    queue = multiprocessing.Queue()
    events_process = multiprocessing.Process(target=run_bbot_multiprocess, args=(queue,))
    events_process.start()
    events_process.join()
    events = queue.get()
    assert len(events) >= 3
    scan_events = [e for e in events if e["type"] == "SCAN"]
    assert len(scan_events) == 2
    assert any(e["data"] == "test@blacklanternsecurity.com" for e in events)


def test_bbot_fastapi(bbot_httpserver):
    bbot_httpserver.expect_request("/").respond_with_data("test@blacklanternsecurity.com")
    fastapi_process = start_fastapi_server()

    try:
        # wait for the server to start with a timeout of 60 seconds
        start_time = time.time()
        while True:
            try:
                response = httpx.get("http://127.0.0.1:8978/ping")
                response.raise_for_status()
                break
            except httpx.HTTPError:
                if time.time() - start_time > 60:
                    raise TimeoutError("Server did not start within 60 seconds.")
                time.sleep(0.1)
                continue

        # run a scan
        response = httpx.get(
            "http://127.0.0.1:8978/start",
            params={"targets": ["http://127.0.0.1:8888", "blacklanternsecurity.com"]},
            timeout=100,
        )
        events = response.json()
        assert len(events) >= 3
        scan_events = [e for e in events if e["type"] == "SCAN"]
        assert len(scan_events) == 2
        assert any(e["data"] == "test@blacklanternsecurity.com" for e in events)

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
        [python_executable, "-m", "uvicorn", "bbot.test.fastapi_test:app", "--port", "8978"], cwd=cwd, env=env
    )
    return process
