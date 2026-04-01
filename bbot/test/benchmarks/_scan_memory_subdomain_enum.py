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

from bbot.scanner import Scanner

SUBDOMAIN_ENUM_COUNT = int(sys.argv[1])

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
                    f"sub{i}.blacklanternsecurity.com",
                    "DNS_NAME",
                    parent=root_event,
                    context=f"benchmark DNS_NAME {i}",
                )
                await scan.ingress_module.queue_event(dns_event, {})


asyncio.run(run())
_, peak = tracemalloc.get_traced_memory()
tracemalloc.stop()
print(f"PEAK_MB:{round(peak / 1024 / 1024, 2)}")
