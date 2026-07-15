from .base import ModuleTestBase
from bbot.modules.base import BaseModule


class TestWAFBypass(ModuleTestBase):
    targets = ["protected.test", "direct.test"]
    module_name = "waf_bypass"
    modules_overrides = ["waf_bypass", "http"]
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
                    url, "URL", parent=self.scan.root_event, tags=["cloudflare", "in-scope", "status-200"]
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

        # Mock ASN lookups via asndb
        asn_helper = module_test.scan.helpers.asn

        async def mock_lookup_ip(ip, include_subnets=False):
            if str(ip) == self.DIRECT_IP or str(ip).startswith("127.0.0."):
                return self.api_response_direct
            elif str(ip) == self.PROTECTED_IP:
                return self.api_response_cloudflare
            return None

        module_test.monkeypatch.setattr(asn_helper.client, "lookup_ip", mock_lookup_ip)

        expect_args = {"method": "GET", "uri": "/", "headers": {"Host": "protected.test"}}
        respond_args = {"status": 200, "response_data": "HELLO THERE!"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Patch WAF bypass get_url_content to control similarity outcome
        waf_module = module_test.scan.modules["waf_bypass"]

        class FakeResponse:
            def __init__(self, text, status_code):
                self.text = text
                self.status_code = status_code

        async def fake_get_url_content(self_waf, url, ip=None):
            if "protected.test" in url and (ip is None or ip == "127.0.0.1"):
                return FakeResponse("PROTECTED CONTENT!", 200)
            else:
                return FakeResponse("ERROR!", 404)

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
        waf_bypass_events = [e for e in events if e.type == "FINDING"]
        assert waf_bypass_events, "No FINDING event produced"

        correct_description = [
            e
            for e in waf_bypass_events
            if "WAF Bypass Confirmed - Direct IPs: 127.0.0.1 for http://protected.test:8888/. Similarity 100.00%"
            in e.data["description"]
        ]
        assert correct_description, "Incorrect description"


class TestWAFBypassTagRecognition(ModuleTestBase):
    """Regression: waf_bypass keys off the flat cloud-provider tags cloudcheck emits
    post-`Migrate cloudcheck to host_metadata` refactor. Both `cloudflare` and `imperva`
    tags must trigger protected-domain detection."""

    targets = ["evilcorp.com"]
    modules_overrides = ["waf_bypass"]

    async def setup_after_prep(self, module_test):
        pass

    async def check(self, module_test, events):
        waf_module = module_test.scan.modules["waf_bypass"]

        async def fake_resolve(host):
            return []

        module_test.monkeypatch.setattr(waf_module.helpers.dns, "resolve", fake_resolve)

        async def fake_get_url_content(url, ip=None):
            return None

        import types

        module_test.monkeypatch.setattr(
            waf_module, "get_url_content", types.MethodType(fake_get_url_content, waf_module), raising=True
        )

        for tag in ("cloudflare", "imperva"):
            waf_module.protected_domains = {}
            url_event = module_test.scan.make_event(
                f"http://{tag}-protected.test/",
                "URL",
                parent=module_test.scan.root_event,
                tags=[tag, "in-scope", "status-200"],
            )
            await waf_module.handle_event(url_event)
            assert f"{tag}-protected.test" in waf_module.protected_domains, (
                f"waf_bypass did not recognize {tag!r}-tagged URL as protected"
            )

        # sanity: an untagged URL is not treated as protected
        waf_module.protected_domains = {}
        untagged = module_test.scan.make_event(
            "http://plain.test/",
            "URL",
            parent=module_test.scan.root_event,
            tags=["in-scope", "status-200"],
        )
        await waf_module.handle_event(untagged)
        assert "plain.test" not in waf_module.protected_domains, (
            "waf_bypass should not flag untagged URLs as protected"
        )
