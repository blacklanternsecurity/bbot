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
