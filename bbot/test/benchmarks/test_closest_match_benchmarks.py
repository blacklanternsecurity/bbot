import pytest
import random
from bbot.core.helpers.misc import closest_match


class TestClosestMatchBenchmarks:
    """
    Benchmark tests for closest_match operations.

    This function is critical for BBOT's DNS brute forcing, where it finds the best
    matching parent event among thousands of choices. Performance here directly impacts
    scan throughput and DNS mutation efficiency.
    """

    def setup_method(self):
        """Setup common test data"""
        # Set deterministic seed for consistent benchmark results
        random.seed(42)  # Fixed seed for reproducible results

        # Generate test data of different sizes and complexity
        self.small_choices = self._generate_small_choices()
        self.medium_choices = self._generate_medium_choices()
        self.large_choices = self._generate_large_choices()
        self.dns_choices = self._generate_dns_choices()

    def _generate_small_choices(self):
        """Generate small dataset (like few parent events)"""
        return ["example.com", "test.com", "demo.com", "sample.com", "trial.com"]

    def _generate_medium_choices(self):
        """Generate medium dataset (like typical scan)"""
        choices = []
        for i in range(1000):
            # Generate realistic domain names
            domain = f"subdomain{i}.example{i % 10}.com"
            choices.append(domain)
        return choices

    def _generate_large_choices(self):
        """Generate large dataset (like complex scan with many parent events)"""
        choices = []
        for i in range(10000):
            # Generate realistic domain names with more variety
            tld = random.choice(["com", "net", "org", "io", "co", "dev"])
            domain = f"subdomain{i}.example{i % 100}.{tld}"
            choices.append(domain)
        return choices

    def _generate_dns_choices(self):
        """Generate realistic DNS parent event choices (like actual BBOT usage)"""
        choices = []

        # Common TLDs
        tlds = ["com", "net", "org", "io", "co", "dev", "test", "local"]

        # Generate parent domains with realistic patterns
        for i in range(5000):
            # Base domain patterns
            if i % 10 == 0:
                # Simple domains
                domain = f"example{i}.{random.choice(tlds)}"
            elif i % 5 == 0:
                # Multi-level domains
                domain = f"sub{i}.example{i}.{random.choice(tlds)}"
            else:
                # Complex domains
                domain = f"level1{i}.level2{i}.example{i}.{random.choice(tlds)}"

            choices.append(domain)

        return choices

    @pytest.mark.benchmark(group="closest_match")
    def test_large_dns_lookup(self, benchmark):
        """Benchmark closest_match with large DNS scan workload (many parent events)"""

        def find_large_match():
            return closest_match("subdomain5678.example50.com", self.large_choices)

        result = benchmark.pedantic(find_large_match, iterations=50, rounds=10)
        assert result is not None

    @pytest.mark.benchmark(group="closest_match")
    def test_realistic_dns_workload(self, benchmark):
        """Benchmark closest_match with realistic BBOT DNS parent event choices"""

        def find_realistic_match():
            return closest_match("subdomain123.example5.com", self.dns_choices)

        result = benchmark.pedantic(find_realistic_match, iterations=50, rounds=10)
        assert result is not None
