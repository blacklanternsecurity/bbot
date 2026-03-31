"""
Memory benchmarks for BBOT scan patterns.

Runs real scans against a local HTTP server and measures peak traced
memory via tracemalloc. The key metric is `total_memory_mb` in extra_info,
which the benchmark report script picks up and displays as MB.

Scanner construction is done outside the tracemalloc window because it
pulls in presets, module loading, and other heavy one-time setup that can
exceed 400 MB in a pytest process -- far more than the actual scan -- and
would set the tracemalloc peak before a single event is created.
"""

import gc
import asyncio
import threading
import tracemalloc
from http.server import HTTPServer, BaseHTTPRequestHandler

import pytest

from bbot.scanner import Scanner


NUM_PAGES = 500
BODY_SIZE = 500_000  # 500 KB per page


class _BenchmarkHTTPHandler(BaseHTTPRequestHandler):
    """Serves an index page linking to sub-pages with large bodies."""

    def do_GET(self):
        if self.path == "/":
            links = "".join(f'<a href="/page{i}">page{i}</a>\n' for i in range(NUM_PAGES))
            body = f"<html><body>{links}</body></html>"
        elif self.path.startswith("/page"):
            i = self.path.replace("/page", "")
            links = f'<a href="/data{i}/info">info</a><a href="/data{i}/details">details</a>'
            body = f"<html><body><h1>Page {i}</h1>{links}{'A' * BODY_SIZE}</body></html>"
        elif self.path.startswith("/data"):
            body = "<html><body>data endpoint</body></html>"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


def _start_server():
    server = HTTPServer(("127.0.0.1", 0), _BenchmarkHTTPHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, port


def _measure_peak(scan_factory, run_scan):
    """Build the scanner untraced, then measure only scan execution memory."""
    # Phase 1: build the scanner (untraced)
    scan, cleanup = scan_factory()

    # Phase 2: trace only the scan execution
    gc.collect()
    if tracemalloc.is_tracing():
        tracemalloc.stop()
    tracemalloc.start()
    try:
        asyncio.run(run_scan(scan))
    finally:
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        if cleanup:
            cleanup()
    return round(peak / 1024 / 1024, 2)


# ---------------------------------------------------------------------------
# 1) Web crawl -- httpx visits many pages, excavate processes bodies
# ---------------------------------------------------------------------------


def _web_crawl_factory():
    server, port = _start_server()
    scan = Scanner(
        f"http://127.0.0.1:{port}/",
        modules=["httpx"],
        output_modules=["python"],
        config={
            "dns": {"disable": True},
            "scope": {"search_distance": 0},
            "web": {"spider_distance": 10, "spider_depth": 10, "spider_links_per_page": NUM_PAGES},
            "speculate": True,
            "excavate": True,
            "aggregate": False,
            "cloudcheck": False,
            "modules": {"httpx": {"batch_size": 25}},
        },
        force_start=True,
    )
    return scan, server.shutdown


async def _web_crawl_run(scan):
    events = []
    async for event in scan.async_start():
        events.append(event)


class TestWebCrawlMemory:
    """Measures peak memory during a realistic web crawl with large pages."""

    @pytest.mark.benchmark(group="memory_scan_patterns")
    def test_web_crawl(self, benchmark):
        peak_mb = _measure_peak(_web_crawl_factory, _web_crawl_run)
        benchmark.extra_info["total_memory_mb"] = peak_mb
        benchmark.extra_info["num_pages"] = NUM_PAGES
        benchmark.pedantic(lambda: None, iterations=1, rounds=1, warmup_rounds=0)


# ---------------------------------------------------------------------------
# 2) Subdomain enum -- many DNS_NAME events, no heavy bodies
# ---------------------------------------------------------------------------

SUBDOMAIN_ENUM_COUNT = 5000


def _subdomain_enum_factory():
    scan = Scanner(
        "blacklanternsecurity.com",
        modules=[],
        output_modules=["python"],
        config={
            "dns": {"disable": True},
            "scope": {"search_distance": 0},
            "web": {"spider_distance": 0, "spider_depth": 0},
            "speculate": False,
            "excavate": True,
            "aggregate": False,
            "cloudcheck": False,
        },
        force_start=True,
    )
    return scan, None


async def _subdomain_enum_run(scan):
    events = []
    injected = False

    async for event in scan.async_start():
        events.append(event)
        if event.type == "SCAN" and not injected:
            injected = True
            root_event = scan.root_event
            for i in range(SUBDOMAIN_ENUM_COUNT):
                dns_event = scan.make_event(
                    f"sub{i}.blacklanternsecurity.com",
                    "DNS_NAME",
                    parent=root_event,
                    context=f"benchmark DNS_NAME {i}",
                )
                await scan.ingress_module.queue_event(dns_event, {})

    return events


class TestSubdomainEnumMemory:
    """Measures peak memory during a large subdomain enumeration."""

    @pytest.mark.benchmark(group="memory_scan_patterns")
    def test_subdomain_enum(self, benchmark):
        peak_mb = _measure_peak(_subdomain_enum_factory, _subdomain_enum_run)
        benchmark.extra_info["total_memory_mb"] = peak_mb
        benchmark.extra_info["num_subdomains"] = SUBDOMAIN_ENUM_COUNT
        benchmark.pedantic(lambda: None, iterations=1, rounds=1, warmup_rounds=0)
