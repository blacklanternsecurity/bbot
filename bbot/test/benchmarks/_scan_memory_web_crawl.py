"""
Subprocess script for web crawl memory benchmark.

Launches a local HTTP server with NUM_PAGES pages (each BODY_SIZE bytes),
runs a BBOT scan against it, and prints peak tracemalloc memory to stdout.

Invoked by test_scan_memory.py — not meant to be run directly.
"""

import gc
import sys
import asyncio
import threading
import tracemalloc
import importlib.util
from http.server import HTTPServer, BaseHTTPRequestHandler

import psutil

from bbot.scanner import Scanner
from bbot.test.benchmarks._memory_helpers import (
    LiveEventTracker,
    RSSSampler,
    event_census,
    lineage_census,
    queue_residence,
    emit_metrics_json,
)

NUM_PAGES = int(sys.argv[1])
BODY_SIZE = int(sys.argv[2])
CHECKPOINT_EVERY = 200  # mid-scan census cadence (events seen)

HTTP_MODULE = "httpx" if importlib.util.find_spec("bbot.modules.httpx") else "http"


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            links = "".join(f'<a href="/page{i}">page{i}</a>' for i in range(NUM_PAGES))
            body = "<html><body>" + links + "</body></html>"
        elif self.path.startswith("/page"):
            i = self.path.replace("/page", "")
            links = f'<a href="/data{i}/info">info</a><a href="/data{i}/details">details</a>'
            body = "<html><body><h1>Page " + i + "</h1>" + links + "A" * BODY_SIZE + "</body></html>"
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

    def log_message(self, *a):
        pass


server = HTTPServer(("127.0.0.1", 0), H)
port = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()

scan = Scanner(
    f"http://127.0.0.1:{port}/",
    modules=[HTTP_MODULE],
    exclude_output_modules=["csv", "json", "txt"],
    config={
        "dns": {"minimal": True},
        "scope": {"search_distance": 0},
        "web": {"spider_distance": 10, "spider_depth": 10, "spider_links_per_page": NUM_PAGES},
        "speculate": True,
        "excavate": True,
        "aggregate": False,
        "cloudcheck": False,
    },
    force_start=True,
)


async def run():
    await scan._prep()
    gc.collect()
    if tracemalloc.is_tracing():
        tracemalloc.stop()

    tracker = LiveEventTracker()
    tracker.install()
    sampler = RSSSampler(interval_s=0.2)
    sampler.start()
    tracemalloc.start()

    # Count emitted events without holding strong refs. Holding them in a
    # list would inflate live-event counts artificially — production
    # callers iterate and discard.
    events_seen = 0
    checkpoints = []
    proc = psutil.Process()
    async for event in scan.async_start():
        del event
        events_seen += 1
        if events_seen % CHECKPOINT_EVERY == 0:
            checkpoints.append(
                {
                    "events_seen": events_seen,
                    "rss_mb": round(proc.memory_info().rss / 1024 / 1024, 2),
                    **tracker.census(),
                    "residence": queue_residence(scan, tracker),
                }
            )

    sampler.stop()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    emit_metrics_json(
        peak_tracemalloc_mb=round(peak / 1024 / 1024, 2),
        num_pages=NUM_PAGES,
        body_size=BODY_SIZE,
        events_collected=events_seen,
        rss=sampler.metrics(),
        census=event_census(),
        lineage=lineage_census(),
        end_residence=queue_residence(scan, tracker),
        checkpoints=checkpoints,
    )


asyncio.run(run())
server.shutdown()
