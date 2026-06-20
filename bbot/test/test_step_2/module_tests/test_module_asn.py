from unittest.mock import AsyncMock, patch

from .base import ModuleTestBase


class TestASNHelper(ModuleTestBase):
    """Test ASN module with real asndb lookup against Google's 8.8.8.8 (AS15169)."""

    targets = ["8.8.8.8"]
    module_name = "asn"
    modules_overrides = ["asn", "speculate"]
    config_overrides = {"scope": {"report_distance": 2}, "speculate": True}

    def check(self, module_test, events):
        asn_events = [e for e in events if e.type == "ASN"]
        assert asn_events, "No ASN event produced"
        assert any(isinstance(e.data, dict) and e.data.get("asn", 0) == 15169 for e in asn_events)


class TestASNUnknownHandling(ModuleTestBase):
    """Test that no ASN events are emitted for private IPs (unknown ASN)."""

    targets = ["192.168.1.1"]
    module_name = "asn"
    modules_overrides = ["asn", "speculate"]
    config_overrides = {"scope": {"report_distance": 2}, "speculate": True}

    def check(self, module_test, events):
        asn_events = [e for e in events if e.type == "ASN"]
        assert not asn_events, (
            f"Should not emit any ASN events for private IP, but found: {[e.data for e in asn_events]}"
        )


class TestASNCacheKeyType(ModuleTestBase):
    """Regression: asn_to_subnets() must hit the asndb cache after ip_to_subnets() populated it.

    The asndb LRU cache stores with int keys. If asn_to_subnets() passes a
    string key, every report-phase lookup misses the cache and hits the network.
    """

    targets = ["8.8.8.8"]
    module_name = "asn"
    modules_overrides = ["asn", "speculate"]
    config_overrides = {"scope": {"report_distance": 2}, "speculate": True}

    async def check(self, module_test, events):
        asn_events = [e for e in events if e.type == "ASN"]
        assert asn_events, "No ASN event produced"

        asn_helper = module_test.scan.helpers.asn
        client = asn_helper.client

        cached_asns = list(client._asn_cache.keys())
        assert cached_asns, "asndb cache is empty after scan"
        for key in cached_asns:
            assert isinstance(key, int), f"Cache key {key!r} is {type(key).__name__}, expected int"

        # asn_to_subnets() with an int should hit the cache without any network call
        test_asn = cached_asns[0]
        with patch.object(client, "request", new_callable=AsyncMock) as mock_request:
            result = await asn_helper.asn_to_subnets(test_asn)
            assert result["asn"] != 0, "asn_to_subnets() returned UNKNOWN_ASN despite cached data"
            mock_request.assert_not_called()


class TestASNReportNoNetwork(ModuleTestBase):
    """Regression: report() uses metadata stored during handle_event() with zero network calls."""

    targets = ["8.8.8.8"]
    module_name = "asn"
    modules_overrides = ["asn", "speculate"]
    config_overrides = {"scope": {"report_distance": 2}, "speculate": True}

    async def check(self, module_test, events):
        asn_events = [e for e in events if e.type == "ASN"]
        assert asn_events, "No ASN event produced"

        asn_module = module_test.scan.modules["asn"]

        # handle_event() should have stored metadata for report()
        assert asn_module.asn_metadata, "asn_metadata is empty after scan"
        for asn_number, metadata in asn_module.asn_metadata.items():
            assert isinstance(asn_number, int), f"asn_metadata key {asn_number!r} should be int"
            assert metadata["subnet_count"] > 0
            assert metadata["name"]
            assert metadata["description"]

        # report() should not touch the network at all
        asn_helper = module_test.scan.helpers.asn
        with patch.object(asn_helper.client, "request", new_callable=AsyncMock) as mock_request:
            await asn_module.report()
            mock_request.assert_not_called()

        # Verify the report table was emitted via logging
        log_text = "\n".join(r.message for r in module_test.caplog.records)
        for asn_number in asn_module.asn_metadata:
            assert f"AS{asn_number}" in log_text, f"AS{asn_number} not found in report log output"
