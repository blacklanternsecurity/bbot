"""
Subprocess script for subdomain enumeration memory benchmark.

Injects SUBDOMAIN_ENUM_COUNT synthetic DNS_NAME events into a scan
and prints peak tracemalloc memory to stdout.

Invoked by test_scan_memory.py — not meant to be run directly.
"""

import gc
import sys
import asyncio
import tracemalloc

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

SUBDOMAIN_ENUM_COUNT = int(sys.argv[1])
CHECKPOINT_EVERY = 1000  # mid-scan census cadence (events seen)

scan = Scanner(
    "example.com",
    modules=[],
    exclude_output_modules=["csv", "json", "txt"],
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
    injected = False
    proc = psutil.Process()
    async for event in scan.async_start():
        events_seen += 1
        is_scan = event.type == "SCAN"
        # Read what we need; don't hold the event reference.
        if is_scan and not injected:
            injected = True
            root_event = scan.root_event
            for i in range(SUBDOMAIN_ENUM_COUNT):
                dns_event = scan.make_event(
                    f"sub{i}.example.com",
                    "DNS_NAME",
                    parent=root_event,
                    context=f"benchmark DNS_NAME {i}",
                )
                await scan.ingress_module.queue_event(dns_event, {})
                del dns_event
            del root_event
        del event
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
        num_subdomains=SUBDOMAIN_ENUM_COUNT,
        events_collected=events_seen,
        rss=sampler.metrics(),
        census=event_census(),
        lineage=lineage_census(),
        end_residence=queue_residence(scan, tracker),
        checkpoints=checkpoints,
    )


asyncio.run(run())
