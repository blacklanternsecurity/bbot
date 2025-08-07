from .base import ModuleTestBase
from bbot.modules.base import BaseModule
import json


class TestWAFBypass(ModuleTestBase):
    targets = ["protected.test", "direct.test"]
    module_name = "waf_bypass"
    modules_overrides = ["waf_bypass", "httpx"]
    config_overrides = {
        "scope": {"report_distance": 2},
        "modules": {"waf_bypass": {"search_ip_neighbors": True, "neighbor_cidr": 30}},
    }

    PROTECTED_IP = "127.0.0.129"
    DIRECT_IP = "127.0.0.2"

    api_response_direct = {
        "asn": 15169,
        "subnets": ["127.0.0.0/25"],
        "asn_name": "ACME-ORG",
        "org": "ACME-ORG",
        "country": "US",
    }

    api_response_cloudflare = {
        "asn": 13335,
        "asn_name": "CLOUDFLARENET",
        "country": "US",
        "ip": "127.0.0.129",
        "org": "Cloudflare, Inc.",
        "rir": "ARIN",
        "subnets": ["127.0.0.128/25"],
    }

    class DummyModule(BaseModule):
        watched_events = ["DNS_NAME"]
        _name = "dummy_module"
        events_seen = []

        async def handle_event(self, event):
            if event.data == "protected.test":
                await self.helpers.sleep(0.5)
                self.events_seen.append(event.data)
                url = "http://protected.test:8888/"
                url_event = self.scan.make_event(
                    url, "URL", parent=self.scan.root_event, tags=["cdn-cloudflare", "in-scope", "status-200"]
                )
                if url_event is not None:
                    await self.emit_event(url_event)

            elif event.data == "direct.test":
                await self.helpers.sleep(0.5)
                self.events_seen.append(event.data)
                url = "http://direct.test:8888/"
                url_event = self.scan.make_event(
                    url, "URL", parent=self.scan.root_event, tags=["in-scope", "status-200"]
                )
                if url_event is not None:
                    await self.emit_event(url_event)

    async def setup_after_prep(self, module_test):
        from bbot.core.helpers.asn import ASNHelper

        await module_test.mock_dns(
            {
                "protected.test": {"A": [self.PROTECTED_IP]},
                "direct.test": {"A": [self.DIRECT_IP]},
                "": {"A": []},
            }
        )

        self.module_test = module_test

        self.dummy_module = self.DummyModule(module_test.scan)
        module_test.scan.modules["dummy_module"] = self.dummy_module

        module_test.monkeypatch.setattr(ASNHelper, "asndb_url", "http://127.0.0.1:8888/v1/ip/")

        expect_args = {"method": "GET", "uri": "/v1/ip/127.0.0.2"}
        respond_args = {
            "response_data": json.dumps(self.api_response_direct),
            "status": 200,
            "content_type": "application/json",
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/", "headers": {"Host": "protected.test"}}
        respond_args = {"status": 200, "response_data": "HELLO THERE!"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Patch WAF bypass get_url_content to control similarity outcome
        waf_module = module_test.scan.modules["waf_bypass"]

        async def fake_get_url_content(self_waf, url, ip=None):
            if "protected.test" in url and (ip == None or ip == "127.0.0.1"):
                return "PROTECTED CONTENT!"
            else:
                return "Error!!"

        import types

        module_test.monkeypatch.setattr(
            waf_module,
            "get_url_content",
            types.MethodType(fake_get_url_content, waf_module),
            raising=True,
        )

        # 7. Monkeypatch tldextract so base_domain is never empty
        def fake_tldextract(domain):
            import types as _t

            return _t.SimpleNamespace(top_domain_under_public_suffix=domain)

        module_test.monkeypatch.setattr(
            waf_module.helpers,
            "tldextract",
            fake_tldextract,
            raising=True,
        )

    def check(self, module_test, events):
        waf_bypass_events = [e for e in events if e.type == "VULNERABILITY"]
        assert waf_bypass_events, "No VULNERABILITY event produced"

        correct_description = [
            e
            for e in waf_bypass_events
            if "WAF Bypass Confirmed - Direct IPs: 127.0.0.1 for http://protected.test:8888/. Similarity 100.00%"
            in e.data["description"]
        ]
        assert correct_description, "Incorrect description"
