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

        module_test.monkeypatch.setattr(ASNHelper, "asndb_url", "http://127.0.0.1:8888/v1/ip/")

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

        # Verify name field is not the unknown placeholder
        assert any(e.data.get("name") and e.data.get("name") != "unknown" for e in asn_events)
