"""
Intercept-pipeline throughput benchmark.

Measures how fast events flow through BBOT's intercept chain (dnsresolve,
cloudcheck, speculate, etc.) under a workload dominated by IP_ADDRESS events.
Useful for detecting regressions or improvements anywhere in the per-event
intercept path — single-threaded modules in this chain bound overall scan
throughput, so changes there are most easily observed here.

The scenario uses a small private CIDR as the target. Speculate expands it
into IP_ADDRESS events, which then traverse the intercept chain. No external
network calls are made.

Run with:
    pytest bbot/test/benchmarks/test_intercept_throughput_benchmarks.py -v --benchmark-only
"""

import asyncio

import pytest

from bbot.scanner import Scanner


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
