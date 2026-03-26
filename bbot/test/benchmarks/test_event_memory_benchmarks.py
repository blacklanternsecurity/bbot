import random
import tracemalloc

import pytest

from bbot.core.event.base import make_event


class TestEventMemoryBenchmarks:
    """
    Benchmark tests for event memory footprint.

    Simulates realistic scan workloads and measures per-event memory consumption.
    Uses pytest-benchmark's extra_info to record memory metrics alongside timing data.
    """

    def setup_method(self):
        random.seed(42)
        self.common_tags = [
            "in-scope",
            "distance-0",
            "subdomain",
            "ipv4",
            "resolved",
            "a-record",
            "aaaa-record",
            "private-ip",
            "microsoft",
            "cdn",
            "open-port",
            "status-200",
            "web",
            "dir",
            "endpoint",
        ]

    def _generate_scan_events(self, count):
        """Generate a realistic mix of events simulating a subdomain enum + web crawl scan."""
        rng = random.Random(42)
        subdomains = ["www", "api", "mail", "ftp", "admin", "test", "dev", "staging", "blog", "cdn", "assets", "app"]
        tlds = ["com", "org", "net", "io"]
        events = []

        for i in range(count):
            kind = i % 5
            if kind <= 1:
                # DNS_NAME (~40%)
                sub = rng.choice(subdomains)
                data = f"{sub}{i}.example.{rng.choice(tlds)}"
                event_type = "DNS_NAME"
            elif kind == 2:
                # IP_ADDRESS (~20%)
                data = f"{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
                event_type = "IP_ADDRESS"
            elif kind == 3:
                # URL_UNVERIFIED (~20%)
                sub = rng.choice(subdomains)
                data = f"http://{sub}{i}.example.{rng.choice(tlds)}/path{i}"
                event_type = "URL_UNVERIFIED"
            else:
                # OPEN_TCP_PORT (~20%)
                data = f"{rng.choice(subdomains)}{i}.example.{rng.choice(tlds)}:{rng.choice([80, 443, 8080, 8443])}"
                event_type = "OPEN_TCP_PORT"

            e = make_event(data, event_type, dummy=True)
            # 5-10 tags per event, typical of a real scan
            num_tags = 5 + (i % 6)
            for tag in self.common_tags[:num_tags]:
                e.add_tag(tag)
            events.append(e)

        return events

    def _measure_memory(self, count):
        """Create count events under tracemalloc and return (events, total_bytes, per_event_bytes)."""
        # Warm up to exclude one-time allocations
        _warmup = self._generate_scan_events(50)
        del _warmup

        tracemalloc.start()
        snapshot_before = tracemalloc.take_snapshot()

        events = self._generate_scan_events(count)

        snapshot_after = tracemalloc.take_snapshot()
        tracemalloc.stop()

        stats = snapshot_after.compare_to(snapshot_before, "lineno")
        total_bytes = sum(s.size_diff for s in stats if s.size_diff > 0)
        per_event = total_bytes / count

        return events, total_bytes, per_event

    @pytest.mark.benchmark(group="event_memory_scan_simulation")
    def test_event_memory_medium_scan(self, benchmark):
        """Simulate a medium scan (~10K events) and measure per-event memory."""
        count = 10_000

        # Use benchmark for timing the event creation
        benchmark.pedantic(lambda: self._generate_scan_events(count), iterations=1, rounds=3)

        # Measure memory separately (tracemalloc + benchmark don't mix well)
        events, total_bytes, per_event = self._measure_memory(count)
        benchmark.extra_info["total_memory_bytes"] = total_bytes
        benchmark.extra_info["per_event_bytes"] = round(per_event, 1)
        benchmark.extra_info["total_memory_mb"] = round(total_bytes / 1024 / 1024, 2)
        benchmark.extra_info["event_count"] = count

    @pytest.mark.benchmark(group="event_memory_scan_simulation")
    def test_event_memory_large_scan(self, benchmark):
        """Simulate a large scan (~50K events) and measure per-event memory."""
        count = 50_000

        benchmark.pedantic(lambda: self._generate_scan_events(count), iterations=1, rounds=3)

        events, total_bytes, per_event = self._measure_memory(count)
        benchmark.extra_info["total_memory_bytes"] = total_bytes
        benchmark.extra_info["per_event_bytes"] = round(per_event, 1)
        benchmark.extra_info["total_memory_mb"] = round(total_bytes / 1024 / 1024, 2)
        benchmark.extra_info["event_count"] = count
