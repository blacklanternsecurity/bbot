"""
Intercept-pipeline throughput benchmarks.

Measures how fast events flow through BBOT's intercept chain (dnsresolve,
cloudcheck, speculate, portfilter, excavate). Single-threaded modules in
this chain bound overall scan throughput, so changes there are most easily
observed here.

Two scenarios:

  - `TestInterceptThroughputBenchmarks`: real scan, CIDR target. Speculate
    expands the CIDR into IP_ADDRESS events that traverse the chain. One
    host per event (the IP itself), so per-event cloudcheck cost is minimal.

  - `TestInterceptCloudcheckDNSThroughput`: synthetic DNS_NAME events with
    populated `resolved_hosts`, injected directly into the intercept chain.
    Mirrors the heavy-subdomain-enum hot path where each event carries a
    hostname plus a small set of resolved IPs, so cloudcheck runs N+1
    lookups per event. This is the path that exhibits queue backlog in
    real scans; the CIDR scenario underestimates it.

Run with:
    pytest bbot/test/benchmarks/test_intercept_throughput_benchmarks.py -v --benchmark-only
"""

import asyncio
from contextlib import suppress

import pytest

from bbot.scanner import Scanner
from bbot.constants import SCAN_STATUS_RUNNING


def _run_scan(cidr):
    config = {
        "scope": {"search_distance": 0, "report_distance": 0},
        "dns": {"disable": True},
        "modules": {"speculate": {"ports": "80,443"}},
        "omit_event_types": [],
    }

    scan = Scanner(cidr, config=config)
    event_counts = {}

    async def _inner():
        async for event in scan.async_start():
            event_counts[event.type] = event_counts.get(event.type, 0) + 1

    asyncio.run(_inner())
    return event_counts


class TestInterceptThroughputBenchmarks:
    """Throughput of the intercept pipeline under IP-heavy workloads."""

    @pytest.mark.benchmark(group="intercept_throughput_small")
    def test_intercept_throughput_small(self, benchmark):
        """/22 (1024 IPs) — modest fan-out, dominated by per-event intercept cost."""
        counts = benchmark.pedantic(_run_scan, args=("10.0.0.0/22",), rounds=3, warmup_rounds=1)
        assert counts.get("IP_RANGE", 0) >= 1, f"expected ≥1 IP_RANGE event, got {counts}"

    @pytest.mark.benchmark(group="intercept_throughput_medium")
    def test_intercept_throughput_medium(self, benchmark):
        """/20 (4096 IPs) — larger fan-out exercising the intercept queue under load."""
        counts = benchmark.pedantic(_run_scan, args=("10.0.0.0/20",), rounds=3, warmup_rounds=1)
        assert counts.get("IP_RANGE", 0) >= 1, f"expected ≥1 IP_RANGE event, got {counts}"


def _run_dns_throughput(num_events, resolved_ips_per_event, busy_tasks, inherit_from_parent=False):
    """
    Push `num_events` synthetic DNS_NAME events through the intercept chain
    and return throughput in events/sec.

    Each event carries `resolved_ips_per_event` resolved IPs, so cloudcheck
    looks up the original hostname plus N IPs. `busy_tasks` spawns no-op
    coroutines that pump the event loop, simulating contention from other
    work in a real scan.

    If `inherit_from_parent` is True, all events share a single parent
    event that has already been through cloudcheck. This exercises the
    parent-inheritance fast path where children skip the lookup loop.
    """
    # disable dns (no resolution) and speculate (no port expansion); this leaves
    # cloudcheck + excavate as the only intercept stages between ingress/egress.
    # cloudcheck is off-by-default under bbot/test/test.conf, so explicitly enable it.
    config = {
        "scope": {"search_distance": 0, "report_distance": 0},
        "dns": {"disable": True},
        "speculate": False,
        "cloudcheck": True,
        "omit_event_types": [],
    }
    scan = Scanner("blacklanternsecurity.com", config=config)

    async def _inner():
        await scan._prep()

        intercept_modules = scan.intercept_modules
        cloudcheck_idx = next((i for i, m in enumerate(intercept_modules) if m.name == "cloudcheck"), -1)
        assert cloudcheck_idx >= 0, f"cloudcheck not in intercept chain: {[m.name for m in intercept_modules]}"
        # we only run workers up to and including cloudcheck. excavate's worker
        # would race with us on cloudcheck.outgoing (= excavate.incoming) and
        # consume events before the drain can see them. _scan_egress has no
        # outgoing queue at all (it fans out to scan modules).
        active_chain = intercept_modules[: cloudcheck_idx + 1]
        first = active_chain[0]
        cloudcheck_mod = active_chain[-1]
        drain_queue = cloudcheck_mod.outgoing_event_queue

        # synthesize events: each one looks like a freshly-resolved DNS_NAME
        # with a populated `resolved_hosts` set
        resolved_pool = [f"10.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}" for i in range(resolved_ips_per_event)]

        # If we're benchmarking the parent-inheritance fast path, build a
        # parent event that's already been through cloudcheck and stash a
        # `_cloudcheck_hosts` snapshot containing every child's host_original
        # plus the resolved IPs. Children whose hosts are a subset of that
        # snapshot will inherit and skip the lookup phase.
        parent_event = scan.root_event
        if inherit_from_parent:
            parent_event = scan.make_event(
                "parent.bench.example.com",
                "DNS_NAME",
                parent=scan.root_event,
                tags=["resolved", "a-record"],
            )
            # parent's resolved_hosts must cover every child's host set so
            # cloudcheck's inheritance subset check passes. each child uses
            # unique data (so ScanIngress dedup lets them through) but a
            # host set that's a subset of parent's.
            child_hosts = {f"sub{i}.bench.example.com" for i in range(num_events)}
            parent_event.resolved_hosts = child_hosts | set(resolved_pool)
            parent_event.scope_distance = 0
            parent_event._cloudcheck_done = True
            # empty host_metadata = no provider matches recorded; inheritance
            # path only needs the done flag + host coverage, not match data
            parent_event._host_metadata = {}

        events = []
        for i in range(num_events):
            event = scan.make_event(
                f"sub{i}.bench.example.com",
                "DNS_NAME",
                parent=parent_event,
                tags=["resolved", "a-record"],
            )
            event.resolved_hosts = resolved_pool
            event.scope_distance = 0
            events.append(event)

        # the intercept worker loops exit immediately while `scan.stopping` is true,
        # and `stopping` is true unless the scan's status_code is in the RUNNING band.
        # async_start() normally flips this; we're bypassing async_start so we flip it ourselves.
        await scan._set_status(SCAN_STATUS_RUNNING)

        # start workers only for ingress → … → cloudcheck (no downstream race)
        worker_tasks = []
        for mod in active_chain:
            for _ in range(mod.module_threads):
                worker_tasks.append(asyncio.create_task(mod._worker()))

        # optional event-loop pressure
        busy = [asyncio.create_task(_busy_loop()) for _ in range(busy_tasks)]

        # drain task — pull from the last intercept module's outgoing queue
        received = 0

        async def _drain():
            nonlocal received
            while received < num_events:
                event, _kwargs = await drain_queue.get()
                received += 1

        # inject + measure
        loop = asyncio.get_event_loop()
        start = loop.time()
        for event in events:
            first.incoming_event_queue.put_nowait((event, {}))
        try:
            await asyncio.wait_for(_drain(), timeout=300)
        finally:
            for t in worker_tasks + busy:
                t.cancel()
            for t in worker_tasks + busy:
                with suppress(asyncio.CancelledError, BaseException):
                    await t
            elapsed = loop.time() - start

        # tear down scan resources
        with suppress(BaseException):
            await scan._cleanup()

        return received / max(elapsed, 1e-9)

    return asyncio.run(_inner())


async def _busy_loop():
    """
    Mimics another module doing periodic small work — yields control about
    every millisecond. A tight `sleep(0)` spin would 100%-saturate the loop
    and catastrophically starve a single-coro intercept worker; this is
    closer to what a real concurrent module looks like.
    """
    while True:
        await asyncio.sleep(0.001)


class TestInterceptCloudcheckDNSThroughput:
    """
    Synthetic DNS_NAME throughput — direct injection into the intercept chain.

    Faithfully reproduces the heavy-subdomain-enum hot path where each
    DNS_NAME event carries 2-5 resolved hosts. This stresses cloudcheck's
    per-event lookup loop, which is the path observed to back up in
    production scans.
    """

    @pytest.mark.benchmark(group="cloudcheck_dns_throughput_quiet")
    def test_dns_throughput_quiet(self, benchmark):
        """1000 DNS_NAME events × 3 resolved IPs, no event-loop pressure."""
        rate = benchmark.pedantic(_run_dns_throughput, args=(1000, 3, 0), rounds=3, warmup_rounds=1)
        benchmark.extra_info["events_per_sec"] = round(rate, 1)
        assert rate > 0, f"expected positive throughput, got {rate}"

    @pytest.mark.benchmark(group="cloudcheck_dns_throughput_loaded")
    def test_dns_throughput_loaded(self, benchmark):
        """500 DNS_NAME events × 3 resolved IPs, 20 busy tasks pumping the loop."""
        rate = benchmark.pedantic(_run_dns_throughput, args=(500, 3, 20), rounds=2, warmup_rounds=0)
        benchmark.extra_info["events_per_sec"] = round(rate, 1)
        assert rate > 0, f"expected positive throughput, got {rate}"

    @pytest.mark.benchmark(group="cloudcheck_dns_throughput_inherited")
    def test_dns_throughput_inherited(self, benchmark):
        """
        1000 DNS_NAME events × 3 resolved IPs, all sharing a parent that has
        already been through cloudcheck. Exercises the parent-inheritance
        fast path that skips per-event lookups.
        """
        rate = benchmark.pedantic(
            _run_dns_throughput,
            args=(1000, 3, 0),
            kwargs={"inherit_from_parent": True},
            rounds=3,
            warmup_rounds=1,
        )
        benchmark.extra_info["events_per_sec"] = round(rate, 1)
        assert rate > 0, f"expected positive throughput, got {rate}"
