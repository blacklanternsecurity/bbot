"""
Subprocess script for the parallel-chains memory benchmark.

Mirrors the real-scale pattern: many independent targets being scanned
concurrently, each producing its own deep chain. Even when each chain
is naturally serial in its fetch cadence, the union across hundreds
of chains is where bodies pile up — the pathology a single-seed
``_scan_memory_deep_chain.py`` cannot reproduce.

The HTTP server serves a path scheme of ``/seed{S}/page{N}``. Page N
of seed S links to page N+1 of the same seed (no cross-seed links,
strict per-seed chain). NUM_SEEDS targets are passed to the scanner
so the spider runs all chains concurrently.

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

NUM_SEEDS = int(sys.argv[1])
CHAIN_LENGTH = int(sys.argv[2])
BODY_SIZE = int(sys.argv[3])
CHECKPOINT_EVERY = 500  # mid-scan census cadence (events seen)

HTTP_MODULE = "httpx" if importlib.util.find_spec("bbot.modules.httpx") else "http"


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        # Path format: /seed{S}/page{N}
        parts = self.path.strip("/").split("/")
        if len(parts) != 2 or not parts[0].startswith("seed") or not parts[1].startswith("page"):
            self.send_response(404)
            self.end_headers()
            return
        try:
            seed_idx = int(parts[0][len("seed") :])
            page_idx = int(parts[1][len("page") :])
        except ValueError:
            self.send_response(404)
            self.end_headers()
            return
        if seed_idx >= NUM_SEEDS or page_idx >= CHAIN_LENGTH:
            self.send_response(404)
            self.end_headers()
            return

        # Page N links only to page N+1 within the same seed (no cross-seed links).
        if page_idx + 1 < CHAIN_LENGTH:
            link = f'<a href="/seed{seed_idx}/page{page_idx + 1}">next</a>'
        else:
            link = ""
        body = f"<html><body><h1>seed{seed_idx} page{page_idx}</h1>{link}{'A' * BODY_SIZE}</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *a):
        pass


server = HTTPServer(("127.0.0.1", 0), H)
port = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()

# NUM_SEEDS independent targets — the spider runs all chains concurrently.
targets = [f"http://127.0.0.1:{port}/seed{i}/page0" for i in range(NUM_SEEDS)]
scan = Scanner(
    *targets,
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
        num_seeds=NUM_SEEDS,
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
