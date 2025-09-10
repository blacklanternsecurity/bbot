import pytest
import random
from bbot.core.helpers.misc import weighted_shuffle


class TestWeightedShuffleBenchmarks:
    """
    Benchmark tests for weighted_shuffle operations.

    This function is critical for BBOT's queue management, where it shuffles
    incoming queues based on module priority weights. Performance here directly
    impacts scan throughput and responsiveness.
    """

    def setup_method(self):
        """Setup common test data"""
        # Set deterministic seed for consistent benchmark results
        random.seed(42)  # Fixed seed for reproducible results

        # Generate test data of different sizes and complexity
        self.small_data = self._generate_small_dataset()
        self.medium_data = self._generate_medium_dataset()
        self.large_data = self._generate_large_dataset()
        self.priority_weights = self._generate_priority_weights()

    def _generate_small_dataset(self):
        """Generate small dataset (like few modules)"""
        return {"items": ["module_a", "module_b", "module_c"], "weights": [0.6, 0.3, 0.1]}

    def _generate_medium_dataset(self):
        """Generate medium dataset (like typical scan)"""
        items = [f"module_{i}" for i in range(20)]
        weights = [random.uniform(0.1, 1.0) for _ in range(20)]
        return {"items": items, "weights": weights}

    def _generate_large_dataset(self):
        """Generate large dataset (like complex scan with many modules)"""
        items = [f"module_{i}" for i in range(100)]
        weights = [random.uniform(0.1, 1.0) for _ in range(100)]
        return {"items": items, "weights": weights}

    def _generate_priority_weights(self):
        """Generate realistic priority weights (like BBOT module priorities)"""
        # BBOT uses priorities 1-5, where lower priority = higher weight
        # Weights are calculated as [5] + [6 - m.priority for m in modules]
        priorities = [5] + [6 - p for p in [1, 2, 3, 4, 5]] * 20  # 5 + 5*20 = 105 items
        items = [f"queue_{i}" for i in range(len(priorities))]
        return {"items": items, "weights": priorities}

    @pytest.mark.benchmark(group="weighted_shuffle")
    def test_typical_queue_shuffle(self, benchmark):
        """Benchmark weighted shuffle with typical BBOT scan workload"""

        def shuffle_typical():
            return weighted_shuffle(self.medium_data["items"], self.medium_data["weights"])

        result = benchmark(shuffle_typical)
        assert len(result) == 20
        assert all(item in result for item in self.medium_data["items"])

    @pytest.mark.benchmark(group="weighted_shuffle")
    def test_priority_queue_shuffle(self, benchmark):
        """Benchmark weighted shuffle with realistic BBOT priority weights"""

        def shuffle_priorities():
            return weighted_shuffle(self.priority_weights["items"], self.priority_weights["weights"])

        result = benchmark(shuffle_priorities)
        assert len(result) == len(self.priority_weights["items"])
        assert all(item in result for item in self.priority_weights["items"])
