import pytest
import random
import string
from bbot.core.helpers.misc import make_ip_type, is_ip


class TestIPAddressBenchmarks:
    """
    Benchmark tests for IP address processing operations.

    These tests measure the performance of BBOT-level IP functions which are
    critical for network scanning efficiency and could benefit from different
    underlying implementations.
    """

    def setup_method(self):
        """Setup common test data"""
        # Set deterministic seed for consistent benchmark results
        random.seed(42)  # Fixed seed for reproducible results

        # Generate test data of different types and sizes
        self.valid_ips = self._generate_valid_ips()
        self.invalid_ips = self._generate_invalid_ips()
        self.mixed_data = self._generate_mixed_data()

    def _generate_valid_ips(self):
        """Generate valid IP addresses for testing"""
        valid_ips = []

        # IPv4 addresses
        for i in range(1000):
            valid_ips.append(
                f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            )

        # IPv6 addresses
        for i in range(500):
            ipv6_parts = []
            for j in range(8):
                ipv6_parts.append(f"{random.randint(0, 65535):x}")
            valid_ips.append(":".join(ipv6_parts))

        # Network addresses
        for i in range(500):
            base_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.0"
            valid_ips.append(f"{base_ip}/{random.randint(8, 30)}")

        # IP ranges
        for i in range(200):
            start_ip = (
                f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 200)}"
            )
            end_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(201, 254)}"
            valid_ips.append(f"{start_ip}-{end_ip}")

        return valid_ips

    def _generate_invalid_ips(self):
        """Generate invalid IP addresses for testing"""
        invalid_ips = []

        # Malformed IPv4
        for i in range(500):
            invalid_ips.append(
                f"{random.randint(256, 999)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
            )
            invalid_ips.append(f"{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}")
            invalid_ips.append(
                f"{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
            )

        # Malformed IPv6
        for i in range(300):
            ipv6_parts = []
            for j in range(random.randint(5, 10)):  # Wrong number of parts
                ipv6_parts.append(f"{random.randint(0, 65535):x}")
            invalid_ips.append(":".join(ipv6_parts))

        # Random strings
        for i in range(200):
            length = random.randint(5, 20)
            invalid_ips.append("".join(random.choices(string.ascii_letters + string.digits, k=length)))

        return invalid_ips

    def _generate_mixed_data(self):
        """Generate mixed valid/invalid data for realistic testing"""
        mixed = []
        mixed.extend(self.valid_ips[:500])  # First 500 valid
        mixed.extend(self.invalid_ips[:500])  # First 500 invalid
        # Use deterministic shuffle with fixed seed for consistent results
        random.seed(42)  # Reset seed before shuffle
        random.shuffle(mixed)  # Shuffle for realistic distribution
        return mixed

    @pytest.mark.benchmark(group="ip_validation")
    def test_is_ip_performance(self, benchmark):
        """Benchmark IP validation performance with mixed data"""

        def validate_ips():
            valid_count = 0
            for ip in self.mixed_data:
                if is_ip(ip):
                    valid_count += 1
            return valid_count

        result = benchmark(validate_ips)
        assert result > 0

    @pytest.mark.benchmark(group="ip_type_detection")
    def test_make_ip_type_performance(self, benchmark):
        """Benchmark IP type detection performance"""

        def detect_ip_types():
            type_count = 0
            for ip in self.valid_ips:
                try:
                    make_ip_type(ip)
                    type_count += 1
                except Exception:
                    pass
            return type_count

        result = benchmark(detect_ip_types)
        assert result > 0

    @pytest.mark.benchmark(group="ip_processing")
    def test_mixed_ip_operations(self, benchmark):
        """Benchmark combined IP validation + type detection"""

        def process_ips():
            processed = 0
            for ip in self.mixed_data:
                if is_ip(ip):
                    try:
                        make_ip_type(ip)
                        processed += 1
                    except Exception:
                        pass
            return processed

        result = benchmark(process_ips)
        assert result > 0
