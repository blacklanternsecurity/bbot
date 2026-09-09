"""
Scan throughput benchmark — measures end-to-end HTTP probing performance.

Runs a real BBOT scan against a local httpserver, measuring how many
HTTP_RESPONSE events are produced per second through the full scan pipeline.

Automatically detects the available HTTP scan module (httpx or http/blasthttp).

Run with:
    pytest bbot/test/benchmarks/test_scan_throughput_benchmarks.py -v --benchmark-only
"""

import asyncio
import importlib.util
from threading import Thread
from http.server import HTTPServer, BaseHTTPRequestHandler

import pytest


BENCH_PORT = 18899

# On 3.0: scan module is "httpx", output module is "http"
# On blasthttp branch: scan module is "http", output module is "webhook"
HTTP_MODULE = "httpx" if importlib.util.find_spec("bbot.modules.httpx") else "http"


class _BenchHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler — returns 200 with a small HTML body for all paths."""

    def do_GET(self):
        body = f"<html><title>{self.path}</title><body>ok</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module", autouse=True)
def bench_httpserver():
    server = HTTPServer(("127.0.0.1", BENCH_PORT), _BenchHandler)
    t = Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield server
    server.shutdown()


def _run_scan(num_urls):
    """Run a scan with num_urls directory targets, return (http_responses, total_events)."""
    from bbot.scanner import Scanner

    targets = [f"http://127.0.0.1:{BENCH_PORT}/dir{i}/" for i in range(num_urls)]
    config = {
        "web": {"http_timeout": 10, "http_retries": 0, "ssl_verify_target": False},
        "scope": {"search_distance": 0, "report_distance": 0},
        "modules": {"speculate": {"ports": str(BENCH_PORT)}},
        "excavate": False,
        "aggregate": False,
        "cloudcheck": False,
        "omit_event_types": [],
    }

    scan = Scanner(*targets, modules=[HTTP_MODULE], config=config)
    event_counts = {}

    async def _inner():
        async for event in scan.async_start():
            event_counts[event.type] = event_counts.get(event.type, 0) + 1

    asyncio.run(_inner())
    return event_counts.get("HTTP_RESPONSE", 0), sum(event_counts.values())


class TestScanThroughputBenchmarks:
    """Benchmark full scan pipeline throughput."""

    def test_scan_throughput_100(self, benchmark):
        """100 target URLs through the full scan pipeline."""
        result = benchmark.pedantic(_run_scan, args=(100,), rounds=3, warmup_rounds=1)
        http_responses, total = result
        assert http_responses >= 100, f"Expected at least 100 HTTP_RESPONSE events, got {http_responses}"

    def test_scan_throughput_1000(self, benchmark):
        """1000 target URLs through the full scan pipeline."""
        result = benchmark.pedantic(_run_scan, args=(1000,), rounds=3, warmup_rounds=1)
        http_responses, total = result
        assert http_responses >= 1000, f"Expected at least 1000 HTTP_RESPONSE events, got {http_responses}"
