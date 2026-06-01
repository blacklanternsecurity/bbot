"""
Memory benchmarks for BBOT scan patterns.

Each benchmark launches a scan as a subprocess so tracemalloc / RSS
measurements are not contaminated by pytest's own allocations. The
subprocess emits a single ``METRICS_JSON:`` line containing four
measurement angles, all of which are surfaced to pytest-benchmark via
``benchmark.extra_info``:

  - ``peak_tracemalloc_mb``: Python-side peak (legacy headline metric;
    misses Rust / lxml / yara allocations).
  - ``rss.peak_rss_mb`` / ``rss.end_rss_mb`` / ``rss.retention_rss_mb``:
    OS-level RSS sampled every ~200 ms. ``retention_rss_mb`` is the
    median of the last 25% of samples — the metric most sensitive to
    "stuck for the rest of the scan" pathology.
  - ``census``: live BaseEvent count by type + HTTP_RESPONSE body MB
    at scan-end. Answers "where is the memory going?".
  - ``lineage``: every live event's parent chain walked back to the
    seed; reports max chain depth and which seeds pin the most events.
    Answers "is the chain holding things alive?".

A backward-compatible ``PEAK_MB:`` line is still emitted by
``_memory_helpers.emit_metrics_json`` for any external readers.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest


NUM_PAGES = 1000
BODY_SIZE = 1_000_000  # 1 MB per page → 1 GB served
SUBDOMAIN_ENUM_COUNT = 20_000
DEEP_CHAIN_LENGTH = 200
DEEP_CHAIN_BODY_SIZE = 1_000_000  # 1 MB per page

# Parallel-chains workload: simulates real-scale scans with many concurrent
# targets. Even when each chain is naturally serial, the union across chains
# is where bodies pile up — the pathology a single deep chain cannot reproduce.
PARALLEL_NUM_SEEDS = 50
PARALLEL_CHAIN_LENGTH = 30
PARALLEL_BODY_SIZE = 500_000

_BENCHMARKS_DIR = Path(__file__).parent


def _run_scan_subprocess(script_path: Path, *args: str) -> dict:
    """Run a scan script in a clean subprocess; return parsed metrics dict."""
    result = subprocess.run(
        [sys.executable, str(script_path), *args],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Scan subprocess failed:\n{result.stderr[-2000:]}")
    metrics = None
    for line in result.stdout.strip().splitlines():
        if line.startswith("METRICS_JSON:"):
            metrics = json.loads(line[len("METRICS_JSON:") :])
    if metrics is None:
        raise RuntimeError(f"No METRICS_JSON in subprocess output:\n{result.stdout[-2000:]}")
    return metrics


def _record(benchmark, metrics: dict, **extra) -> None:
    """Flatten the metrics dict into ``benchmark.extra_info``."""
    benchmark.extra_info["total_memory_mb"] = metrics["peak_tracemalloc_mb"]
    benchmark.extra_info["events_collected"] = metrics["events_collected"]

    rss = metrics["rss"]
    benchmark.extra_info["peak_rss_mb"] = rss["peak_rss_mb"]
    benchmark.extra_info["end_rss_mb"] = rss["end_rss_mb"]
    benchmark.extra_info["retention_rss_mb"] = rss["retention_rss_mb"]
    benchmark.extra_info["rss_samples"] = rss["samples"]
    benchmark.extra_info["scan_duration_s"] = rss["duration_s"]

    census = metrics["census"]
    benchmark.extra_info["live_events"] = census["live_events"]
    benchmark.extra_info["live_by_type"] = census["by_type"]
    benchmark.extra_info["http_response_body_mb"] = census["http_response_body_mb"]
    benchmark.extra_info["http_response_with_body"] = census["http_response_with_body"]

    lineage = metrics["lineage"]
    benchmark.extra_info["max_chain_depth"] = lineage["max_chain_depth"]
    benchmark.extra_info["total_pinned_events"] = lineage["total_pinned_events"]
    benchmark.extra_info["top_pinning_seeds"] = lineage["seeds"][:5]

    # Mid-scan checkpoints expose body-byte peaks before minimize() runs
    # and the live-event growth curve that end-of-scan census misses.
    checkpoints = metrics.get("checkpoints", [])
    benchmark.extra_info["checkpoints"] = checkpoints
    if checkpoints:
        benchmark.extra_info["peak_live_events_midscan"] = max(c["live_events"] for c in checkpoints)
        benchmark.extra_info["peak_body_mb_midscan"] = max(c["http_response_body_mb"] for c in checkpoints)
        # Residence peaks: max in-pipeline (queued or being handled) vs
        # max chain-only (alive solely because the parent chain pins them).
        residences = [c["residence"] for c in checkpoints if "residence" in c]
        if residences:
            benchmark.extra_info["peak_in_pipeline_midscan"] = max(r["in_pipeline"] for r in residences)
            benchmark.extra_info["peak_chain_only_midscan"] = max(r["chain_only"] for r in residences)
            benchmark.extra_info["peak_queue_total_midscan"] = max(r["queue_total"] for r in residences)

    end_residence = metrics.get("end_residence")
    if end_residence is not None:
        benchmark.extra_info["end_residence"] = end_residence

    for k, v in extra.items():
        benchmark.extra_info[k] = v


class TestWebCrawlMemory:
    """Wide-and-shallow web crawl: every page hangs off ``/``."""

    @pytest.mark.benchmark(group="memory_scan_patterns")
    def test_memory_use_web_crawl(self, benchmark):
        metrics = _run_scan_subprocess(
            _BENCHMARKS_DIR / "_scan_memory_web_crawl.py",
            str(NUM_PAGES),
            str(BODY_SIZE),
        )
        _record(benchmark, metrics, num_pages=NUM_PAGES, body_size=BODY_SIZE)
        benchmark.pedantic(lambda: None, iterations=1, rounds=1, warmup_rounds=0)


class TestSubdomainEnumMemory:
    """Synthetic breadth-only workload: ``SUBDOMAIN_ENUM_COUNT`` injected DNS_NAME events."""

    @pytest.mark.benchmark(group="memory_scan_patterns")
    def test_memory_use_subdomain_enum(self, benchmark):
        metrics = _run_scan_subprocess(
            _BENCHMARKS_DIR / "_scan_memory_subdomain_enum.py",
            str(SUBDOMAIN_ENUM_COUNT),
        )
        _record(benchmark, metrics, num_subdomains=SUBDOMAIN_ENUM_COUNT)
        benchmark.pedantic(lambda: None, iterations=1, rounds=1, warmup_rounds=0)


class TestDeepChainMemory:
    """
    Deep-and-narrow spider: page N links only to page N+1.

    Designed to expose chain-retention pathology — long parent lineage
    with HTTP_RESPONSE bodies pinned via ``parent`` references. Compare
    ``retention_rss_mb`` and ``max_chain_depth`` against the wide
    workload to gauge how much memory is held by lineage vs. burst.
    """

    @pytest.mark.benchmark(group="memory_scan_patterns")
    def test_memory_use_deep_chain(self, benchmark):
        metrics = _run_scan_subprocess(
            _BENCHMARKS_DIR / "_scan_memory_deep_chain.py",
            str(DEEP_CHAIN_LENGTH),
            str(DEEP_CHAIN_BODY_SIZE),
        )
        _record(
            benchmark,
            metrics,
            chain_length=DEEP_CHAIN_LENGTH,
            body_size=DEEP_CHAIN_BODY_SIZE,
        )
        benchmark.pedantic(lambda: None, iterations=1, rounds=1, warmup_rounds=0)


class TestParallelChainsMemory:
    """
    Many independent chains running concurrently — closest analogue to
    a real-scale scan over many domains.

    A single deep chain doesn't expose body retention because the
    spider is naturally serial within a chain (one fetch at a time).
    Across N independent chains, body windows overlap and bodies pile
    up even though each chain is individually well-behaved. This is
    the workload most relevant to the "20-hour scan over thousands of
    domains" pattern where both body retention and chain retention
    compound.
    """

    @pytest.mark.benchmark(group="memory_scan_patterns")
    def test_memory_use_parallel_chains(self, benchmark):
        metrics = _run_scan_subprocess(
            _BENCHMARKS_DIR / "_scan_memory_parallel_chains.py",
            str(PARALLEL_NUM_SEEDS),
            str(PARALLEL_CHAIN_LENGTH),
            str(PARALLEL_BODY_SIZE),
        )
        _record(
            benchmark,
            metrics,
            num_seeds=PARALLEL_NUM_SEEDS,
            chain_length=PARALLEL_CHAIN_LENGTH,
            body_size=PARALLEL_BODY_SIZE,
        )
        benchmark.pedantic(lambda: None, iterations=1, rounds=1, warmup_rounds=0)
