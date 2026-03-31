"""
Memory benchmarks for BBOT scan patterns.

Each benchmark launches a scan as a subprocess so tracemalloc measurements
are not contaminated by pytest's own allocations. The subprocess writes
peak memory (MB) to stdout, which the test reads and stores in
benchmark extra_info["total_memory_mb"].
"""

import subprocess
import sys
import textwrap

import pytest


NUM_PAGES = 500
BODY_SIZE = 500_000  # 500 KB per page
SUBDOMAIN_ENUM_COUNT = 5000


def _run_scan_subprocess(script: str) -> float:
    """Run a scan script in a clean subprocess, return peak memory in MB."""
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Scan subprocess failed:\n{result.stderr[-2000:]}")
    for line in result.stdout.strip().splitlines():
        if line.startswith("PEAK_MB:"):
            return float(line.split(":", 1)[1])
    raise RuntimeError(f"No PEAK_MB in subprocess output:\n{result.stdout[-2000:]}")


# ---------------------------------------------------------------------------
# 1) Web crawl -- httpx visits many pages, excavate processes bodies
# ---------------------------------------------------------------------------

_WEB_CRAWL_SCRIPT = textwrap.dedent(f"""\
    import gc, asyncio, threading, tracemalloc
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from bbot.scanner import Scanner

    NUM_PAGES = {NUM_PAGES}
    BODY_SIZE = {BODY_SIZE}

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                links = "".join(f'<a href="/page{{i}}">page{{i}}</a>' for i in range(NUM_PAGES))
                body = f"<html><body>{{links}}</body></html>"
            elif self.path.startswith("/page"):
                i = self.path.replace("/page", "")
                links = f'<a href="/data{{i}}/info">info</a><a href="/data{{i}}/details">details</a>'
                body = f"<html><body><h1>Page {{i}}</h1>{{links}}{{"A" * BODY_SIZE}}</body></html>"
            elif self.path.startswith("/data"):
                body = "<html><body>data endpoint</body></html>"
            else:
                self.send_response(404); self.end_headers(); return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body.encode())
        def log_message(self, *a): pass

    server = HTTPServer(("127.0.0.1", 0), H)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    scan = Scanner(
        f"http://127.0.0.1:{{port}}/",
        modules=["httpx"], output_modules=["python"],
        config={{
            "dns": {{"disable": True}},
            "scope": {{"search_distance": 0}},
            "web": {{"spider_distance": 10, "spider_depth": 10, "spider_links_per_page": NUM_PAGES}},
            "speculate": True, "excavate": True, "aggregate": False, "cloudcheck": False,
            "modules": {{"httpx": {{"batch_size": 25}}}},
        }},
        force_start=True,
    )

    async def run():
        await scan._prep()
        gc.collect()
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        tracemalloc.start()
        events = []
        async for event in scan.async_start():
            events.append(event)

    asyncio.run(run())
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    server.shutdown()
    print(f"PEAK_MB:{{round(peak / 1024 / 1024, 2)}}")
""")


class TestWebCrawlMemory:
    """Measures peak memory during a realistic web crawl with large pages."""

    @pytest.mark.benchmark(group="memory_scan_patterns")
    def test_memory_use_web_crawl(self, benchmark):
        peak_mb = _run_scan_subprocess(_WEB_CRAWL_SCRIPT)
        benchmark.extra_info["total_memory_mb"] = peak_mb
        benchmark.extra_info["num_pages"] = NUM_PAGES
        benchmark.pedantic(lambda: None, iterations=1, rounds=1, warmup_rounds=0)


# ---------------------------------------------------------------------------
# 2) Subdomain enum -- many DNS_NAME events, no heavy bodies
# ---------------------------------------------------------------------------

_SUBDOMAIN_ENUM_SCRIPT = textwrap.dedent(f"""\
    import gc, asyncio, tracemalloc
    from bbot.scanner import Scanner

    SUBDOMAIN_ENUM_COUNT = {SUBDOMAIN_ENUM_COUNT}

    scan = Scanner(
        "blacklanternsecurity.com",
        modules=[], output_modules=["python"],
        config={{
            "dns": {{"disable": True}},
            "scope": {{"search_distance": 0}},
            "web": {{"spider_distance": 0, "spider_depth": 0}},
            "speculate": False, "excavate": True, "aggregate": False, "cloudcheck": False,
        }},
        force_start=True,
    )

    async def run():
        await scan._prep()
        gc.collect()
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        tracemalloc.start()
        events = []
        injected = False
        async for event in scan.async_start():
            events.append(event)
            if event.type == "SCAN" and not injected:
                injected = True
                root_event = scan.root_event
                for i in range(SUBDOMAIN_ENUM_COUNT):
                    dns_event = scan.make_event(
                        f"sub{{i}}.blacklanternsecurity.com",
                        "DNS_NAME",
                        parent=root_event,
                        context=f"benchmark DNS_NAME {{i}}",
                    )
                    await scan.ingress_module.queue_event(dns_event, {{}})

    asyncio.run(run())
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(f"PEAK_MB:{{round(peak / 1024 / 1024, 2)}}")
""")


class TestSubdomainEnumMemory:
    """Measures peak memory during a large subdomain enumeration."""

    @pytest.mark.benchmark(group="memory_scan_patterns")
    def test_memory_use_subdomain_enum(self, benchmark):
        peak_mb = _run_scan_subprocess(_SUBDOMAIN_ENUM_SCRIPT)
        benchmark.extra_info["total_memory_mb"] = peak_mb
        benchmark.extra_info["num_subdomains"] = SUBDOMAIN_ENUM_COUNT
        benchmark.pedantic(lambda: None, iterations=1, rounds=1, warmup_rounds=0)
