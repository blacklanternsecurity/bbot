from .base import ModuleTestBase

from bbot.modules import baddns

class BaseTestBaddns(ModuleTestBase):
    modules_overrides = ["baddns"]
    targets = ["bad.dns"]
    config_overrides = {"dns_resolution": True}

    async def dispatchWHOIS(x):
        return None


class TestBaddns_cname_nxdomain(BaseTestBaddns):
    async def setup_after_prep(self, module_test):
        from baddns.lib.whoismanager import WhoisManager
        from baddns.base import get_all_modules

        def select_modules(self):
            selected_modules = []
            for m in get_all_modules():
                if m.name in ["CNAME"]:
                    selected_modules.append(m)
            return selected_modules
        
        mock_data = {"bad.dns": {"CNAME": ["baddns.azurewebsites.net."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
        configure_mock_resolver = module_test.request_fixture.getfixturevalue("configure_mock_resolver")
        mock_resolver = configure_mock_resolver(mock_data)
        module_test.monkeypatch.setattr(module_test.scan.helpers.dns, "resolver", mock_resolver)
        module_test.monkeypatch.setattr(baddns.baddns, "select_modules", select_modules)
        module_test.monkeypatch.setattr(WhoisManager, "dispatchWHOIS", self.dispatchWHOIS)


    def check(self, module_test, events):
        
        assert any(e.data == "baddns.azurewebsites.net" for e in events), "CNAME detection failed"
        assert any(e.type == "VULNERABILITY" for e in events), "Failed to emit VULNERABILITY"
        assert any("baddns-cname" in e.tags for e in events), "Failed to add baddns tag"

class TestBaddns_cname_signature(BaseTestBaddns):

    targets = ["bad.dns:8888"]
    modules_overrides = ["baddns","speculate"]

    async def setup_after_prep(self, module_test):

        from baddns.base import get_all_modules
        from baddns.lib.httpmanager import HttpManager
        from baddns.lib.whoismanager import WhoisManager


        def select_modules(self):
            selected_modules = []
            for m in get_all_modules():
                if m.name in ["CNAME"]:
                    selected_modules.append(m)
            return selected_modules


        
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "<h1>Oops! We couldn&#8217;t find that page.</h1>", "status": 200}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        
        mock_data = {"bad.dns": {"CNAME": ["baddns.bigcartel.com."]}, "baddns.bigcartel.com": {"A": ["127.0.0.1"]}}
        configure_mock_resolver = module_test.request_fixture.getfixturevalue("configure_mock_resolver")
        mock_resolver = configure_mock_resolver(mock_data)
        module_test.monkeypatch.setattr(module_test.scan.helpers.dns, "resolver", mock_resolver)
        module_test.monkeypatch.setattr(baddns.baddns, "select_modules", select_modules)
        module_test.monkeypatch.setattr(HttpManager, "urls_to_try", ["http://127.0.0.1:8888"])
        module_test.monkeypatch.setattr(WhoisManager, "dispatchWHOIS", self.dispatchWHOIS)

    def check(self, module_test, events):


        assert any(e for e in events)
     #   assert any(e.data == "baddns.azurewebsites.net" for e in events), "CNAME detection failed"
        assert any(e.type == "VULNERABILITY" and "bigcartel.com" in e.data["description"] for e in events), "Failed to emit VULNERABILITY"
        assert any("baddns-cname" in e.tags for e in events), "Failed to add baddns tag"