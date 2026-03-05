from .base import ModuleTestBase


class TestASNHelper(ModuleTestBase):
    """Simple test for ASN module using mocked asndb library."""

    targets = ["8.8.8.8"]
    module_name = "asn"
    modules_overrides = ["asn"]
    config_overrides = {"scope": {"report_distance": 2}}

    asndb_response = {
        "asn": 15169,
        "subnets": ["8.8.8.0/24"],
        "asn_name": "GOOGLE",
        "org": "Google LLC",
        "country": "US",
    }

    async def setup_after_prep(self, module_test):
        from unittest.mock import AsyncMock

        asn_helper = module_test.scan.helpers.asn
        asn_helper.client = AsyncMock()
        asn_helper.client.lookup_ip = AsyncMock(return_value=self.asndb_response)
        asn_helper.client.lookup_asn = AsyncMock(return_value=self.asndb_response)

    def check(self, module_test, events):
        asn_events = [e for e in events if e.type == "ASN"]
        assert asn_events, "No ASN event produced"
        assert any(isinstance(e.data, dict) and e.data.get("asn", 0) == 15169 for e in asn_events)


class TestASNUnknownHandling(ModuleTestBase):
    """Test ASN module behavior when asndb returns unknown ASN."""

    targets = ["8.8.8.8"]
    module_name = "asn"
    modules_overrides = ["asn"]
    config_overrides = {"scope": {"report_distance": 2}}

    async def setup_after_prep(self, module_test):
        from unittest.mock import AsyncMock
        from bbot.core.helpers.asn import ASNHelper

        asn_helper = module_test.scan.helpers.asn
        asn_helper.client = AsyncMock()
        asn_helper.client.lookup_ip = AsyncMock(return_value=ASNHelper.UNKNOWN_ASN)

    def check(self, module_test, events):
        # When asndb returns unknown, NO ASN events should be emitted since ASN 0 is reserved
        asn_events = [e for e in events if e.type == "ASN"]
        assert not asn_events, (
            f"Should not emit any ASN events for unknown ASN data, but found: {[e.data for e in asn_events]}"
        )
