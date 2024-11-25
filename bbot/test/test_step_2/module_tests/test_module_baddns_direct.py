from .base import ModuleTestBase
from bbot.modules.base import BaseModule


class BaseTestBaddns(ModuleTestBase):
    modules_overrides = ["baddns_direct"]
    targets = ["bad.dns"]
    config_overrides = {"dns": {"minimal": False}, "cloudcheck": True}


class TestBaddns_direct_cloudflare(BaseTestBaddns):
    targets = ["bad.dns:8888"]
    modules_overrides = ["baddns_direct"]

    async def dispatchWHOIS(self):
        return None

    class DummyModule(BaseModule):
        watched_events = ["DNS_NAME"]
        _name = "dummy_module"
        events_seen = []

        async def handle_event(self, event):
            if event.data == "bad.dns":
                await self.helpers.sleep(0.5)
                self.events_seen.append(event.data)
                url = "http://bad.dns:8888/"
                url_event = self.scan.make_event(
                    url, "URL", parent=self.scan.root_event, tags=["cdn-cloudflare", "in-scope", "status-401"]
                )
                if url_event is not None:
                    await self.emit_event(url_event)

    async def setup_after_prep(self, module_test):
        from baddns.base import BadDNS_base
        from baddns.lib.whoismanager import WhoisManager

        def set_target(self, target):
            return "127.0.0.1:8888"

        self.module_test = module_test

        self.dummy_module = self.DummyModule(module_test.scan)
        module_test.scan.modules["dummy_module"] = self.dummy_module

        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "The specified bucket does not exist", "status": 401}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        await module_test.mock_dns({"bad.dns": {"A": ["127.0.0.1"]}})

        module_test.monkeypatch.setattr(BadDNS_base, "set_target", set_target)
        module_test.monkeypatch.setattr(WhoisManager, "dispatchWHOIS", self.dispatchWHOIS)

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING"
            and "Possible [AWS Bucket Takeover Detection] via direct BadDNS analysis. Indicator: [[Words: The specified bucket does not exist | Condition: and | Part: body] Matchers-Condition: and] Trigger: [self] baddns Module: [CNAME]"
            in e.data["description"]
            for e in events
        ), "Failed to emit FINDING"
        assert any("baddns-cname" in e.tags for e in events), "Failed to add baddns tag"
