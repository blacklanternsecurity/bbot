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


class TestASNCGNATFiltered(ModuleTestBase):
    """CGNAT space (100.64.0.0/10) is not globally routable and has no public ASN, so it must be
    filtered out before any lookup (is_global check, not just is_private)."""

    targets = ["100.64.0.1"]
    module_name = "asn"
    modules_overrides = ["asn", "speculate"]
    config_overrides = {"scope": {"report_distance": 2}, "speculate": True}

    def check(self, module_test, events):
        asn_events = [e for e in events if e.type == "ASN"]
        assert not asn_events, (
            f"Should not emit any ASN events for CGNAT IP, but found: {[e.data for e in asn_events]}"
        )


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
