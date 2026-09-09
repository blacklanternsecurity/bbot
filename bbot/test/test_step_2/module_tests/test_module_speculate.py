from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_URL


class TestSpeculate_Subdirectories(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/subdir1/subdir2/"]
    modules_overrides = ["http", "speculate"]

    async def setup_before_prep(self, module_test):
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
        assert any(e.type == "URL_UNVERIFIED" and e.url == f"{HTTPSERVER_URL}/subdir1/" for e in events)


class TestSpeculate_OpenPorts(ModuleTestBase):
    targets = ["evilcorp.com"]
    modules_overrides = ["speculate", "certspotter", "shodan_idb"]
    config_overrides = {"speculate": True}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "evilcorp.com": {"A": ["127.0.254.1"]},
                "asdf.evilcorp.com": {"A": ["127.0.254.2"]},
            }
        )

        module_test.blasthttp_mock.add_response(
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

        dummy_module = DummyModule(module_test.scan)
        await dummy_module.setup()
        module_test.scan.modules["dummy"] = dummy_module

        # Manually configure speculate module to emit OPEN_TCP_PORT events
        # since the dummy module was added after speculate's setup phase
        speculate_module = module_test.scan.modules["speculate"]
        speculate_module.open_port_consumers = True
        speculate_module._always_emit_open_ports = True

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://api.certspotter.com/v1/issuances?domain=evilcorp.com&include_subdomains=true&expand=dns_names",
            json=[{"dns_names": ["*.asdf.evilcorp.com"]}],
        )

    def check(self, module_test, events):
        events_data = set()
        for e in module_test.scan.modules["dummy"].events:
            events_data.add(e.data)
        assert all(
            x in events_data
            for x in ("evilcorp.com:80", "evilcorp.com:443", "asdf.evilcorp.com:80", "asdf.evilcorp.com:443")
        )


class TestSpeculate_OutOfScopeIPRange(ModuleTestBase):
    """Out-of-scope IP ranges from SPF (or any source) should not be enumerated into individual IPs."""

    targets = ["evilcorp.com"]
    modules_overrides = ["speculate"]
    config_overrides = {"dns": {"minimal": False}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "evilcorp.com": {
                    "A": ["127.0.254.1"],
                    "TXT": ['"v=spf1 ip4:192.168.0.0/24 ~all"'],
                },
            }
        )

        from bbot.modules.base import BaseModule

        class IPCollector(BaseModule):
            _name = "ip_collector"
            watched_events = ["IP_ADDRESS"]
            scope_distance_modifier = 10
            accept_dupes = True

            async def setup(self):
                self.events = []
                return True

            async def handle_event(self, event):
                self.events.append(event)

        collector = IPCollector(module_test.scan)
        await collector.setup()
        module_test.scan.modules["ip_collector"] = collector

    def check(self, module_test, events):
        import ipaddress

        net = ipaddress.ip_network("192.168.0.0/24")
        speculated_ips = [
            e
            for e in module_test.scan.modules["ip_collector"].events
            if e.type == "IP_ADDRESS" and ipaddress.ip_address(e.data) in net
        ]
        assert len(speculated_ips) == 0, (
            f"speculate enumerated {len(speculated_ips)} IPs from out-of-scope IP_RANGE 192.168.0.0/24"
        )


class TestSpeculate_OpenPorts_Portscanner(TestSpeculate_OpenPorts):
    targets = ["evilcorp.com"]
    modules_overrides = ["speculate", "certspotter", "portscan"]
    config_overrides = {"speculate": True}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "evilcorp.com": {"A": ["127.0.254.1"]},
                "asdf.evilcorp.com": {"A": ["127.0.254.2"]},
            }
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

        dummy_module = DummyModule(module_test.scan)
        await dummy_module.setup()
        module_test.scan.modules["dummy"] = dummy_module

        # DON'T manually configure speculate module here - we want it to detect
        # the portscan module and NOT emit OPEN_TCP_PORT events

    def check(self, module_test, events):
        events_data = set()
        for e in module_test.scan.modules["dummy"].events:
            events_data.add(e.data)
        assert not any(
            x in events_data
            for x in ("evilcorp.com:80", "evilcorp.com:443", "asdf.evilcorp.com:80", "asdf.evilcorp.com:443")
        )
