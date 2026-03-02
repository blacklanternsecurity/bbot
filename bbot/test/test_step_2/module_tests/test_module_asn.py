from .base import ModuleTestBase
import json


class TestASNHelper(ModuleTestBase):
    """Simple test for ASN module using mocked ASNHelper HTTP endpoint."""

    targets = ["8.8.8.8"]
    module_name = "asn"
    modules_overrides = ["asn"]
    config_overrides = {"scope": {"report_distance": 2}}

    api_response = {
        "asn": 15169,
        "prefixes": ["8.8.8.0/24"],
        "asn_name": "GOOGLE",
        "org": "Google LLC",
        "country": "US",
    }

    async def setup_after_prep(self, module_test):
        # Point ASNHelper to local test harness
        from bbot.core.helpers.asn import ASNHelper

        module_test.monkeypatch.setattr(ASNHelper, "asndb_ip_url", "http://127.0.0.1:8888/v1/ip/")

        expect_args = {"method": "GET", "uri": "/v1/ip/8.8.8.8"}
        respond_args = {
            "response_data": json.dumps(self.api_response),
            "status": 200,
            "content_type": "application/json",
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        # Ensure at least one ASN event is produced
        asn_events = [e for e in events if e.type == "ASN"]
        assert asn_events, "No ASN event produced"

        # Verify ASN data contains a valid ASN number
        assert any(isinstance(e.data, dict) and e.data.get("asn", 0) > 0 for e in asn_events)


class TestASNUnknownHandling(ModuleTestBase):
    """Test ASN module behavior when API returns no data, leading to UNKNOWN_ASN usage."""

    targets = ["8.8.8.8"]  # Use known public IP but mock response to test unknown ASN handling
    module_name = "asn"
    modules_overrides = ["asn"]
    config_overrides = {"scope": {"report_distance": 2}}

    async def setup_after_prep(self, module_test):
        # Point ASNHelper to local test harness
        from bbot.core.helpers.asn import ASNHelper

        module_test.monkeypatch.setattr(ASNHelper, "asndb_ip_url", "http://127.0.0.1:8888/v1/ip/")

        # Mock API to return 404 (no ASN data found)
        expect_args = {"method": "GET", "uri": "/v1/ip/8.8.8.8"}
        respond_args = {
            "response_data": "Not Found",
            "status": 404,
            "content_type": "text/plain",
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        # When API returns 404, ASN helper should return UNKNOWN_ASN with string "0"
        # but NO ASN events should be emitted since ASN 0 is reserved
        asn_events = [e for e in events if e.type == "ASN"]

        # Should NOT emit any ASN events when ASN data is unknown
        assert not asn_events, (
            f"Should not emit any ASN events for unknown ASN data, but found: {[e.data for e in asn_events]}"
        )
