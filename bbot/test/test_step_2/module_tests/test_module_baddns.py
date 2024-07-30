from .base import ModuleTestBase


class BaseTestBaddns(ModuleTestBase):
    modules_overrides = ["baddns"]
    targets = ["bad.dns"]
    config_overrides = {"dns": {"minimal": False}}

    async def dispatchWHOIS(x):
        return None

    def select_modules(self):
        from baddns.base import get_all_modules

        selected_modules = []
        for m in get_all_modules():
            if m.name in ["CNAME"]:
                selected_modules.append(m)
        return selected_modules


class TestBaddns_cname_nxdomain(BaseTestBaddns):
    async def setup_after_prep(self, module_test):
        from bbot.modules import baddns as baddns_module
        from baddns.lib.whoismanager import WhoisManager

        await module_test.mock_dns(
            {"bad.dns": {"CNAME": ["baddns.azurewebsites.net."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
        )
        module_test.monkeypatch.setattr(baddns_module.baddns, "select_modules", self.select_modules)
        module_test.monkeypatch.setattr(WhoisManager, "dispatchWHOIS", self.dispatchWHOIS)

    def check(self, module_test, events):
        assert any([e.data == "baddns.azurewebsites.net" for e in events]), "CNAME detection failed"
        assert any([e.type == "VULNERABILITY" for e in events]), "Failed to emit VULNERABILITY"
        assert any(["baddns-cname" in e.tags for e in events]), "Failed to add baddns tag"


class TestBaddns_cname_signature(BaseTestBaddns):
    targets = ["bad.dns:8888"]
    modules_overrides = ["baddns", "speculate"]

    async def setup_after_prep(self, module_test):
        from bbot.modules import baddns as baddns_module
        from baddns.base import BadDNS_base
        from baddns.lib.whoismanager import WhoisManager

        def set_target(self, target):
            return "127.0.0.1:8888"

        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "<h1>Oops! We couldn&#8217;t find that page.</h1>", "status": 200}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        await module_test.mock_dns(
            {"bad.dns": {"CNAME": ["baddns.bigcartel.com."]}, "baddns.bigcartel.com": {"A": ["127.0.0.1"]}}
        )
        module_test.monkeypatch.setattr(baddns_module.baddns, "select_modules", self.select_modules)
        module_test.monkeypatch.setattr(BadDNS_base, "set_target", set_target)
        module_test.monkeypatch.setattr(WhoisManager, "dispatchWHOIS", self.dispatchWHOIS)

    def check(self, module_test, events):
        assert any([e for e in events])
        assert any(
            [e.type == "VULNERABILITY" and "bigcartel.com" in e.data["description"] for e in events]
        ), "Failed to emit VULNERABILITY"
        assert any(["baddns-cname" in e.tags for e in events]), "Failed to add baddns tag"
