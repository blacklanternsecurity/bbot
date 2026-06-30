"""
Subprocess script for the deep-chain memory benchmark.

Spawns a local HTTP server that serves a strict linear chain — page N
links only to page N+1, no siblings — and runs a BBOT scan that follows
the entire chain. The discovery pipeline produces a deep parent lineage
(each hop adds URL → HTTP_RESPONSE → URL_UNVERIFIED → URL → … to the
chain), exposing chain-retention pathology that the wide-and-shallow
``_scan_memory_web_crawl.py`` workload masks.

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

CHAIN_LENGTH = int(sys.argv[1])
BODY_SIZE = int(sys.argv[2])
CHECKPOINT_EVERY = 25  # mid-scan census cadence (events seen)

HTTP_MODULE = "httpx" if importlib.util.find_spec("bbot.modules.httpx") else "http"


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.rstrip("/")
        if path in ("", "/"):
            i = 0
        elif path.startswith("/page"):
            try:
                i = int(path[len("/page") :])
            except ValueError:
                self.send_response(404)
                self.end_headers()
                return
        else:
            self.send_response(404)
            self.end_headers()
            return

        # Strict chain: page i links only to page i+1; the last page has no link.
        if i + 1 < CHAIN_LENGTH:
            link = f'<a href="/page{i + 1}">next</a>'
        else:
            link = ""
        body = f"<html><body><h1>Page {i}</h1>{link}{'A' * BODY_SIZE}</body></html>"

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *a):
        pass


server = HTTPServer(("127.0.0.1", 0), H)
port = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()

# spider_distance/depth must exceed chain length so the spider follows
# the full chain. spider_links_per_page=1 matches the server (one link).
scan = Scanner(
    f"http://127.0.0.1:{port}/",
    modules=[HTTP_MODULE],
    exclude_output_modules=["csv", "json", "txt"],
    config={
        "dns": {"minimal": True},
        "scope": {"search_distance": 0},
        "web": {
            "spider_distance": CHAIN_LENGTH + 5,
            "spider_depth": CHAIN_LENGTH + 5,
            "spider_links_per_page": 2,
        },
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
        chain_length=CHAIN_LENGTH,
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
