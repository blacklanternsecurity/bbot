"""
Memory benchmarks for BBOT scan patterns.

Each benchmark launches a scan as a subprocess so tracemalloc measurements
are not contaminated by pytest's own allocations. The subprocess writes
peak memory (MB) to stdout, which the test reads and stores in
benchmark extra_info["total_memory_mb"].
"""

import subprocess
import sys
from pathlib import Path

import pytest


NUM_PAGES = 500
BODY_SIZE = 500_000  # 500 KB per page
SUBDOMAIN_ENUM_COUNT = 5000

_BENCHMARKS_DIR = Path(__file__).parent


def _run_scan_subprocess(script_path: Path, *args: str) -> float:
    """Run a scan script in a clean subprocess, return peak memory in MB."""
    result = subprocess.run(
        [sys.executable, str(script_path), *args],
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


class TestWebCrawlMemory:
    """Measures peak memory during a realistic web crawl with large pages."""

    @pytest.mark.benchmark(group="memory_scan_patterns")
    def test_memory_use_web_crawl(self, benchmark):
        peak_mb = _run_scan_subprocess(
            _BENCHMARKS_DIR / "_scan_memory_web_crawl.py",
            str(NUM_PAGES),
            str(BODY_SIZE),
        )
        benchmark.extra_info["total_memory_mb"] = peak_mb
        benchmark.extra_info["num_pages"] = NUM_PAGES
        benchmark.pedantic(lambda: None, iterations=1, rounds=1, warmup_rounds=0)


class TestSubdomainEnumMemory:
    """Measures peak memory during a large subdomain enumeration."""

    @pytest.mark.benchmark(group="memory_scan_patterns")
    def test_memory_use_subdomain_enum(self, benchmark):
        peak_mb = _run_scan_subprocess(
            _BENCHMARKS_DIR / "_scan_memory_subdomain_enum.py",
            str(SUBDOMAIN_ENUM_COUNT),
        )
        benchmark.extra_info["total_memory_mb"] = peak_mb
        benchmark.extra_info["num_subdomains"] = SUBDOMAIN_ENUM_COUNT
        benchmark.pedantic(lambda: None, iterations=1, rounds=1, warmup_rounds=0)
