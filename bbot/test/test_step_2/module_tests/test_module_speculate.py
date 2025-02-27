from .base import ModuleTestBase


class TestSpeculate_Subdirectories(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/subdir1/subdir2/"]
    modules_overrides = ["httpx", "speculate"]

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/subdir1/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/subdir1/subdir2/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.1:8888/subdir1/" for e in events)


class TestSpeculate_OpenPorts(ModuleTestBase):
    targets = ["evilcorp.com"]
    modules_overrides = ["speculate", "certspotter", "shodan_idb"]
    config_overrides = {"speculate": True}

    async def setup_before_prep(self, module_test):
        await module_test.mock_dns(
            {
                "evilcorp.com": {"A": ["127.0.254.1"]},
                "asdf.evilcorp.com": {"A": ["127.0.254.2"]},
            }
        )

        module_test.httpx_mock.add_response(
            url="https://api.certspotter.com/v1/issuances?domain=evilcorp.com&include_subdomains=true&expand=dns_names",
            json=[{"dns_names": ["*.asdf.evilcorp.com"]}],
        )

        from bbot.modules.base import BaseModule

        class DummyModule(BaseModule):
            _name = "dummy"
            watched_events = ["OPEN_TCP_PORT"]
            scope_distance_modifier = 10
            accept_dupes = True

            async def setup(self):
                self.events = []
                return True

            async def handle_event(self, event):
                self.events.append(event)

        module_test.scan.modules["dummy"] = DummyModule(module_test.scan)

    def check(self, module_test, events):
        events_data = set()
        for e in module_test.scan.modules["dummy"].events:
            events_data.add(e.data)
        assert all(
            x in events_data
            for x in ("evilcorp.com:80", "evilcorp.com:443", "asdf.evilcorp.com:80", "asdf.evilcorp.com:443")
        )


class TestSpeculate_OpenPorts_Portscanner(TestSpeculate_OpenPorts):
    targets = ["evilcorp.com"]
    modules_overrides = ["speculate", "certspotter", "portscan"]
    config_overrides = {"speculate": True}

    def check(self, module_test, events):
        events_data = set()
        for e in module_test.scan.modules["dummy"].events:
            events_data.add(e.data)
        assert not any(
            x in events_data
            for x in ("evilcorp.com:80", "evilcorp.com:443", "asdf.evilcorp.com:80", "asdf.evilcorp.com:443")
        )
