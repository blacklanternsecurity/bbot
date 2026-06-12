import pytest
import string
import random
from bbot.scanner import Scanner


class TestBloomFilterBenchmarks:
    """
    Benchmark tests for Bloom Filter operations.

    These tests measure the performance of bloom filter operations which are
    critical for DNS brute-forcing efficiency in BBOT.
    """

    def setup_method(self):
        """Setup common test data"""
        self.scan = Scanner()

        # Generate test data of different sizes
        self.items_small = self._generate_random_strings(1000)  # 1K items
        self.items_medium = self._generate_random_strings(10000)  # 10K items

    def _generate_random_strings(self, n, length=10):
        """Generate a list of n random strings."""
        # Slightly longer strings for testing performance difference
        length = length + 2  # Make strings 2 chars longer
        return ["".join(random.choices(string.ascii_letters + string.digits, k=length)) for _ in range(n)]

    @pytest.mark.benchmark(group="bloom_filter_operations")
    def test_bloom_filter_dns_mutation_tracking_performance(self, benchmark):
        """Benchmark comprehensive bloom filter operations (add, check, mixed) for DNS brute-forcing"""

        def comprehensive_bloom_operations():
            bloom_filter = self.scan.helpers.bloom_filter(size=8000000)  # 8M bits

            # Phase 1: Add operations (simulating storing tried DNS mutations)
            for item in self.items_small:
                bloom_filter.add(item)

            # Phase 2: Check operations (simulating lookup of existing mutations)
            found_count = 0
            for item in self.items_small:
                if item in bloom_filter:
                    found_count += 1

            # Phase 3: Mixed operations (realistic DNS brute-force simulation)
            # Add new items while checking existing ones
            for i, item in enumerate(self.items_medium[:500]):  # Smaller subset for mixed ops
                bloom_filter.add(item)
                # Every few additions, check some existing items
                if i % 10 == 0:
                    for check_item in self.items_small[i : i + 5]:
                        if check_item in bloom_filter:
                            found_count += 1

            return {
                "items_added": len(self.items_small) + 500,
                "items_checked": found_count,
                "bloom_size": bloom_filter.size,
            }

        result = benchmark(comprehensive_bloom_operations)
        assert result["items_added"] > 1000
        assert result["items_checked"] > 0

    @pytest.mark.benchmark(group="bloom_filter_scalability")
    def test_bloom_filter_large_scale_dns_brute_force(self, benchmark):
        """Benchmark bloom filter performance with large-scale DNS brute-force simulation"""

        def large_scale_simulation():
            bloom_filter = self.scan.helpers.bloom_filter(size=8000000)  # 8M bits

            # Simulate a large DNS brute-force session
            mutations_tried = 0
            duplicate_attempts = 0

            # Add all medium dataset (simulating 10K DNS mutations)
            for item in self.items_medium:
                bloom_filter.add(item)
                mutations_tried += 1

            # Simulate checking for duplicates during brute-force
            for item in self.items_medium[:2000]:  # Check subset for duplicates
                if item in bloom_filter:
                    duplicate_attempts += 1

            # Simulate adding more mutations with duplicate checking
            for item in self.items_small:
                if item not in bloom_filter:  # Only add if not already tried
                    bloom_filter.add(item)
                    mutations_tried += 1
                else:
                    duplicate_attempts += 1

            return {
                "total_mutations_tried": mutations_tried,
                "duplicates_avoided": duplicate_attempts,
                "efficiency_ratio": mutations_tried / (mutations_tried + duplicate_attempts)
                if duplicate_attempts > 0
                else 1.0,
            }

        result = benchmark(large_scale_simulation)
        assert result["total_mutations_tried"] > 10000
        assert result["efficiency_ratio"] > 0
