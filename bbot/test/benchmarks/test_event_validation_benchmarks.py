import pytest
import random
import string
from bbot.scanner import Scanner
from bbot.core.event.base import make_event


class TestEventValidationBenchmarks:
    def setup_method(self):
        """Setup minimal scanner configuration for benchmarking event validation"""
        # Set deterministic random seed for reproducible benchmarks
        random.seed(42)

        # Create a minimal scanner with no modules to isolate event validation performance
        self.scanner_config = {
            "modules": None,  # No modules to avoid overhead
            "output_modules": None,  # No output modules
            "dns": {"disable": True},  # Disable DNS to avoid network calls
            "web": {"http_timeout": 1},  # Minimal timeouts
        }

    def _generate_diverse_targets(self, count=1000):
        """Generate a diverse set of targets that will trigger different event type auto-detection"""
        # Use deterministic random state for reproducible target generation
        rng = random.Random(42)
        targets = []

        # DNS Names (various formats)
        subdomains = ["www", "api", "mail", "ftp", "admin", "test", "dev", "staging", "blog"]
        tlds = ["com", "org", "net", "io", "co.uk", "de", "fr", "jp"]

        for _ in range(count // 10):
            # Standard domains
            targets.append(
                f"{rng.choice(subdomains)}.{rng.choice(['example', 'test', 'evilcorp'])}.{rng.choice(tlds)}"
            )
            # Bare domains
            targets.append(f"{rng.choice(['example', 'test', 'company'])}.{rng.choice(tlds)}")

        # IP Addresses (IPv4 and IPv6)
        for _ in range(count // 15):
            # IPv4
            targets.append(f"{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}")
            # IPv6
            targets.append(f"2001:db8::{rng.randint(1, 9999):x}:{rng.randint(1, 9999):x}")

        # IP Ranges
        for _ in range(count // 20):
            targets.append(f"192.168.{rng.randint(1, 254)}.0/24")
            targets.append(f"10.0.{rng.randint(1, 254)}.0/24")

        # URLs (only supported schemes: http, https)
        url_schemes = ["http", "https"]  # Only schemes supported by BBOT auto-detection
        url_paths = ["", "/", "/admin", "/api/v1", "/login.php", "/index.html"]
        for _ in range(count // 8):
            scheme = rng.choice(url_schemes)
            domain = f"{rng.choice(subdomains)}.example.{rng.choice(tlds)}"
            path = rng.choice(url_paths)
            port = rng.choice(["", ":8080", ":443", ":80", ":8443"])
            targets.append(f"{scheme}://{domain}{port}{path}")

        # Open Ports
        ports = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 8080, 8443, 3389]
        for _ in range(count // 12):
            domain = f"example.{rng.choice(tlds)}"
            port = rng.choice(ports)
            targets.append(f"{domain}:{port}")
            # IPv4 with port
            ip = f"{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
            targets.append(f"{ip}:{port}")

        # Email Addresses
        email_domains = ["example.com", "test.org", "company.net"]
        email_users = ["admin", "test", "info", "contact", "support", "sales"]
        for _ in range(count // 15):
            user = rng.choice(email_users)
            domain = rng.choice(email_domains)
            targets.append(f"{user}@{domain}")
            # Plus addressing
            targets.append(f"{user}+{rng.randint(1, 999)}@{domain}")

        # Mixed/Edge cases that should trigger auto-detection logic
        edge_cases = [
            # Localhost variants
            "localhost",
            "127.0.0.1",
            "::1",
            # Punycode domains
            "xn--e1afmkfd.xn--p1ai",
            "xn--fiqs8s.xn--0zwm56d",
            # Long domains (shortened to avoid issues)
            "very-long-subdomain-name-for-testing.test.com",
            # IP with ports
            "192.168.1.1",
            "10.0.0.1:80",
            # URLs with parameters
            "https://example.com/search?q=test&limit=10",
            "http://api.example.com:8080/v1/users?format=json",
            # More standard domains for better compatibility
            "api.test.com",
            "mail.example.org",
            "secure.company.net",
        ]
        targets.extend(edge_cases)

        # Fill remainder with random variations
        remaining = count - len(targets)
        if remaining > 0:
            for _ in range(remaining):
                choice = rng.randint(1, 4)
                if choice == 1:
                    # Random domain
                    targets.append(f"{''.join(rng.choices(string.ascii_lowercase, k=8))}.com")
                elif choice == 2:
                    # Random IP
                    targets.append(
                        f"{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
                    )
                elif choice == 3:
                    # Random URL
                    targets.append(f"https://{''.join(rng.choices(string.ascii_lowercase, k=8))}.com/path")
                else:
                    # Random email
                    targets.append(f"{''.join(rng.choices(string.ascii_lowercase, k=8))}@example.com")

        # Ensure we have exactly the requested count by removing duplicates and filling as needed
        unique_targets = list(set(targets))

        # If we have too few unique targets, generate more
        while len(unique_targets) < count:
            additional_target = f"filler{len(unique_targets)}.example.com"
            if additional_target not in unique_targets:
                unique_targets.append(additional_target)

        # Return exactly the requested number of unique targets
        return unique_targets[:count]

    def _generate_diverse_event_data(self, count=1000):
        """Generate diverse event data that will trigger different auto-detection paths in make_event"""
        # Use deterministic random state for reproducible data generation
        rng = random.Random(42)
        event_data = []

        # DNS Names (various formats)
        subdomains = ["www", "api", "mail", "ftp", "admin", "test", "dev", "staging", "blog"]
        tlds = ["com", "org", "net", "io", "co.uk", "de", "fr", "jp"]

        for _ in range(count // 10):
            # Standard domains
            event_data.append(
                f"{rng.choice(subdomains)}.{rng.choice(['example', 'test', 'evilcorp'])}.{rng.choice(tlds)}"
            )
            # Bare domains
            event_data.append(f"{rng.choice(['example', 'test', 'company'])}.{rng.choice(tlds)}")

        # IP Addresses (IPv4 and IPv6)
        for _ in range(count // 15):
            # IPv4
            event_data.append(
                f"{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
            )
            # IPv6
            event_data.append(f"2001:db8::{rng.randint(1, 9999):x}:{rng.randint(1, 9999):x}")

        # IP Ranges
        for _ in range(count // 20):
            event_data.append(f"192.168.{rng.randint(1, 254)}.0/24")
            event_data.append(f"10.0.{rng.randint(1, 254)}.0/24")

        # URLs (HTTP/HTTPS)
        url_schemes = ["http", "https"]
        url_paths = ["", "/", "/admin", "/api/v1", "/login.php", "/index.html"]
        for _ in range(count // 8):
            scheme = rng.choice(url_schemes)
            domain = f"{rng.choice(subdomains)}.example.{rng.choice(tlds)}"
            path = rng.choice(url_paths)
            port = rng.choice(["", ":8080", ":443", ":80", ":8443"])
            event_data.append(f"{scheme}://{domain}{port}{path}")

        # Open Ports
        ports = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 8080, 8443, 3389]
        for _ in range(count // 12):
            domain = f"example.{rng.choice(tlds)}"
            port = rng.choice(ports)
            event_data.append(f"{domain}:{port}")
            # IPv4 with port
            ip = f"{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
            event_data.append(f"{ip}:{port}")

        # Email Addresses
        email_domains = ["example.com", "test.org", "company.net"]
        email_users = ["admin", "test", "info", "contact", "support", "sales"]
        for _ in range(count // 15):
            user = rng.choice(email_users)
            domain = rng.choice(email_domains)
            event_data.append(f"{user}@{domain}")
            # Plus addressing
            event_data.append(f"{user}+{rng.randint(1, 999)}@{domain}")

        # Mixed/Edge cases that test auto-detection logic
        edge_cases = [
            # Localhost variants
            "localhost",
            "127.0.0.1",
            "::1",
            # Punycode domains
            "xn--e1afmkfd.xn--p1ai",
            "xn--fiqs8s.xn--0zwm56d",
            # Long domains
            "very-long-subdomain-name-for-testing.test.com",
            # IP with ports
            "192.168.1.1",
            "10.0.0.1:80",
            # URLs with parameters
            "https://example.com/search?q=test&limit=10",
            "http://api.example.com:8080/v1/users?format=json",
            # Standard domains for better compatibility
            "api.test.com",
            "mail.example.org",
            "secure.company.net",
        ]
        event_data.extend(edge_cases)

        # Fill remainder with random variations
        remaining = count - len(event_data)
        if remaining > 0:
            for _ in range(remaining):
                choice = rng.randint(1, 4)
                if choice == 1:
                    # Random domain
                    event_data.append(f"{''.join(rng.choices(string.ascii_lowercase, k=8))}.com")
                elif choice == 2:
                    # Random IP
                    event_data.append(
                        f"{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
                    )
                elif choice == 3:
                    # Random URL
                    event_data.append(f"https://{''.join(rng.choices(string.ascii_lowercase, k=8))}.com/path")
                else:
                    # Random email
                    event_data.append(f"{''.join(rng.choices(string.ascii_lowercase, k=8))}@example.com")

        # Ensure we have exactly the requested count by removing duplicates and filling as needed
        unique_data = list(set(event_data))

        # If we have too few unique entries, generate more
        while len(unique_data) < count:
            additional_data = f"filler{len(unique_data)}.example.com"
            if additional_data not in unique_data:
                unique_data.append(additional_data)

        # Return exactly the requested number of unique data items
        return unique_data[:count]

    @pytest.mark.benchmark(group="event_validation_scan_startup_small")
    def test_event_validation_full_scan_startup_small_batch(self, benchmark):
        """Benchmark full scan startup event validation with small batch (100 targets) for quick iteration"""
        targets = self._generate_diverse_targets(100)

        def validate_event_batch():
            scan = Scanner(*targets, config=self.scanner_config)
            # Count successful event creations and types detected
            event_counts = {}
            total_events = 0

            for event_seed in scan.target.seeds:
                event_type = event_seed.type
                event_counts[event_type] = event_counts.get(event_type, 0) + 1
                total_events += 1

            return {
                "total_events_processed": total_events,
                "unique_event_types": len(event_counts),
                "event_type_breakdown": event_counts,
                "targets_input": len(targets),
            }

        result = benchmark(validate_event_batch)
        assert result["total_events_processed"] == result["targets_input"]  # Should process ALL targets
        assert result["unique_event_types"] >= 3  # Should detect at least DNS_NAME, IP_ADDRESS, URL

    @pytest.mark.benchmark(group="event_validation_scan_startup_large")
    def test_event_validation_full_scan_startup_large_batch(self, benchmark):
        """Benchmark full scan startup event validation with large batch (1000 targets) for comprehensive testing"""
        targets = self._generate_diverse_targets(1000)

        def validate_large_batch():
            scan = Scanner(*targets, config=self.scanner_config)

            # Comprehensive analysis of validation pipeline performance
            validation_metrics = {
                "targets_input": len(targets),
                "events_created": 0,
                "validation_errors": 0,
                "auto_detection_success": 0,
                "type_distribution": {},
                "processing_efficiency": 0.0,
            }

            try:
                for event_seed in scan.target.seeds:
                    validation_metrics["events_created"] += 1
                    event_type = event_seed.type

                    if event_type not in validation_metrics["type_distribution"]:
                        validation_metrics["type_distribution"][event_type] = 0
                    validation_metrics["type_distribution"][event_type] += 1

                    # If we got a valid event type, auto-detection succeeded
                    if event_type and event_type != "UNKNOWN":
                        validation_metrics["auto_detection_success"] += 1

            except Exception:
                validation_metrics["validation_errors"] += 1

            # Calculate efficiency ratio
            if validation_metrics["targets_input"] > 0:
                validation_metrics["processing_efficiency"] = (
                    validation_metrics["events_created"] / validation_metrics["targets_input"]
                )

            return validation_metrics

        result = benchmark(validate_large_batch)
        assert result["events_created"] == result["targets_input"]  # Should process ALL targets successfully
        assert result["processing_efficiency"] == 1.0  # 100% success rate
        assert len(result["type_distribution"]) >= 5  # Should detect multiple event types

    @pytest.mark.benchmark(group="make_event_small")
    def test_make_event_autodetection_small(self, benchmark):
        """Benchmark make_event with auto-detection for small batch (100 items)"""
        event_data = self._generate_diverse_event_data(100)

        def create_events_with_autodetection():
            events_created = []
            type_distribution = {}
            validation_errors = 0

            for data in event_data:
                try:
                    # Test auto-detection by not providing event_type
                    event = make_event(data, dummy=True)
                    events_created.append(event)

                    event_type = event.type
                    type_distribution[event_type] = type_distribution.get(event_type, 0) + 1

                except Exception:
                    validation_errors += 1

            return {
                "events_created": len(events_created),
                "type_distribution": type_distribution,
                "validation_errors": validation_errors,
                "autodetection_success_rate": len(events_created) / len(event_data) if event_data else 0,
            }

        result = benchmark.pedantic(create_events_with_autodetection, iterations=50, rounds=10)
        assert result["events_created"] == len(event_data)  # Should create events for all data
        assert result["validation_errors"] == 0  # Should have no validation errors
        assert len(result["type_distribution"]) >= 3  # Should detect multiple event types
        assert result["autodetection_success_rate"] == 1.0  # 100% success rate

    @pytest.mark.benchmark(group="make_event_large")
    def test_make_event_autodetection_large(self, benchmark):
        """Benchmark make_event with auto-detection for large batch (1000 items)"""
        event_data = self._generate_diverse_event_data(1000)

        def create_large_event_batch():
            performance_metrics = {
                "total_processed": len(event_data),
                "events_created": 0,
                "autodetection_failures": 0,
                "type_distribution": {},
                "processing_efficiency": 0.0,
            }

            for data in event_data:
                try:
                    # Use dummy=True for performance (no scan/parent validation)
                    event = make_event(data, dummy=True)
                    performance_metrics["events_created"] += 1

                    event_type = event.type
                    if event_type not in performance_metrics["type_distribution"]:
                        performance_metrics["type_distribution"][event_type] = 0
                    performance_metrics["type_distribution"][event_type] += 1

                except Exception:
                    performance_metrics["autodetection_failures"] += 1

            # Calculate efficiency ratio
            performance_metrics["processing_efficiency"] = (
                performance_metrics["events_created"] / performance_metrics["total_processed"]
            )

            return performance_metrics

        result = benchmark.pedantic(create_large_event_batch, iterations=50, rounds=10)
        assert result["events_created"] == result["total_processed"]  # Should process all successfully
        assert result["autodetection_failures"] == 0  # Should have no failures
        assert result["processing_efficiency"] == 1.0  # 100% efficiency
        assert len(result["type_distribution"]) >= 5  # Should detect multiple event types

    @pytest.mark.benchmark(group="make_event_explicit_types")
    def test_make_event_explicit_types(self, benchmark):
        """Benchmark make_event when event types are explicitly provided (no auto-detection)"""
        # Create data with explicit type mappings to bypass auto-detection
        test_cases = [
            ("example.com", "DNS_NAME"),
            ("192.168.1.1", "IP_ADDRESS"),
            ("https://example.com", "URL"),
            ("admin@example.com", "EMAIL_ADDRESS"),
            ("example.com:80", "OPEN_TCP_PORT"),
        ] * 20  # 100 total cases

        def create_events_explicit_types():
            events_created = []
            type_distribution = {}

            for data, event_type in test_cases:
                # Explicitly provide event_type to skip auto-detection
                event = make_event(data, event_type=event_type, dummy=True)
                events_created.append(event)

                type_distribution[event_type] = type_distribution.get(event_type, 0) + 1

            return {
                "events_created": len(events_created),
                "type_distribution": type_distribution,
                "bypass_autodetection": True,
            }

        result = benchmark.pedantic(create_events_explicit_types, iterations=50, rounds=10)
        assert result["events_created"] == len(test_cases)  # Should create all events
        assert result["bypass_autodetection"]  # Confirms we bypassed auto-detection
        assert len(result["type_distribution"]) == 5  # Should have exactly 5 types
