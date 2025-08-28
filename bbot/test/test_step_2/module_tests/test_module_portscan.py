from .base import ModuleTestBase


class TestPortscan(ModuleTestBase):
    targets = [
        "www.evilcorp.com",
        "evilcorp.com",
        "8.8.8.8/32",
        "8.8.8.8/24",
        "8.8.4.4",
        "asdf.evilcorp.net",
        "8.8.4.4/24",
    ]
    scan_name = "test_portscan"
    config_overrides = {"modules": {"portscan": {"ports": "443", "wait": 1}}, "dns": {"minimal": False}}

    masscan_output_1 = """{   "ip": "8.8.8.8",   "timestamp": "1680197558", "ports": [ {"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 54} ] }"""
    masscan_output_2 = """{   "ip": "8.8.4.5",   "timestamp": "1680197558", "ports": [ {"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 54} ] }"""
    masscan_output_3 = """{   "ip": "8.8.4.6",   "timestamp": "1680197558", "ports": [ {"port": 631, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 54} ] }"""

    masscan_output_ping = """{   "ip": "8.8.8.8",   "timestamp": "1719862594", "ports": [ {"port": 0, "proto": "icmp", "status": "open", "reason": "none", "ttl": 54} ] }"""

    async def setup_after_prep(self, module_test):
        from bbot.modules.base import BaseModule

        class DummyModule(BaseModule):
            _name = "dummy_module"
            watched_events = ["*"]

            async def handle_event(self, event):
                if event.type == "DNS_NAME":
                    if "dummy" not in event.host:
                        await self.emit_event(f"dummy.{event.data}", "DNS_NAME", parent=event)

        module_test.scan.modules["dummy_module"] = DummyModule(module_test.scan)

        await module_test.mock_dns(
            {
                "www.evilcorp.com": {"A": ["8.8.8.8"]},
                "evilcorp.com": {"A": ["8.8.8.8"]},
                "asdf.evilcorp.net": {"A": ["8.8.4.5"]},
                "dummy.asdf.evilcorp.net": {"A": ["8.8.4.5"]},
                "dummy.evilcorp.com": {"A": ["8.8.4.6"]},
                "dummy.www.evilcorp.com": {"A": ["8.8.4.4"]},
            }
        )

        self.syn_scanned = []
        self.ping_scanned = []
        self.syn_runs = 0
        self.ping_runs = 0

        async def run_masscan(command, *args, **kwargs):
            if "masscan" in command[:2]:
                targets = open(command[11]).read().splitlines()
                yield "["
                if "--ping" in command:
                    self.ping_runs += 1
                    self.ping_scanned += targets
                    yield self.masscan_output_ping
                else:
                    self.syn_runs += 1
                    self.syn_scanned += targets
                    if "8.8.8.0/24" in targets or "8.8.8.8/32" in targets:
                        yield self.masscan_output_1
                    if "8.8.4.0/24" in targets:
                        yield self.masscan_output_2
                        yield self.masscan_output_3
                yield "]"
            else:
                async for l in module_test.scan.helpers.run_live(command, *args, **kwargs):
                    yield l

        module_test.monkeypatch.setattr(module_test.scan.helpers, "run_live", run_masscan)

    def check(self, module_test, events):
        assert set(self.syn_scanned) == {"8.8.8.0/24", "8.8.4.0/24"}
        assert set(self.ping_scanned) == set()
        assert self.syn_runs >= 1
        assert self.ping_runs == 0
        assert 1 == len(
            [e for e in events if e.type == "DNS_NAME" and e.data == "evilcorp.com" and str(e.module) == "TARGET"]
        )
        assert 1 == len(
            [e for e in events if e.type == "DNS_NAME" and e.data == "www.evilcorp.com" and str(e.module) == "TARGET"]
        )
        assert 1 == len(
            [e for e in events if e.type == "DNS_NAME" and e.data == "asdf.evilcorp.net" and str(e.module) == "TARGET"]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "DNS_NAME" and e.data == "dummy.evilcorp.com" and str(e.module) == "dummy_module"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "DNS_NAME" and e.data == "dummy.www.evilcorp.com" and str(e.module) == "dummy_module"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "DNS_NAME" and e.data == "dummy.asdf.evilcorp.net" and str(e.module) == "dummy_module"
            ]
        )
        # the reason these numbers aren't exactly predictable is because we can't predict which one arrives first
        # to the portscan module. Sometimes, one that would normally be deduped is force-emitted because it led to a new open port.
        assert 2 <= len([e for e in events if e.type == "IP_ADDRESS" and e.data == "8.8.8.8"]) <= 4
        assert 2 <= len([e for e in events if e.type == "IP_ADDRESS" and e.data == "8.8.4.4"]) <= 4
        assert 2 <= len([e for e in events if e.type == "IP_ADDRESS" and e.data == "8.8.4.5"]) <= 4
        assert 2 <= len([e for e in events if e.type == "IP_ADDRESS" and e.data == "8.8.4.6"]) <= 4
        assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "8.8.8.8:443"])
        assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "8.8.4.5:80"])
        assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "8.8.4.6:631"])
        assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "evilcorp.com:443"])
        assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "www.evilcorp.com:443"])
        assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "asdf.evilcorp.net:80"])
        assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "dummy.asdf.evilcorp.net:80"])
        assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "dummy.evilcorp.com:631"])
        assert not any(e for e in events if e.type == "OPEN_TCP_PORT" and e.host == "dummy.www.evilcorp.com")


class TestPortscanPingFirst(TestPortscan):
    modules_overrides = {"portscan"}
    config_overrides = {"modules": {"portscan": {"ports": "443", "wait": 1, "ping_first": True}}}

    def check(self, module_test, events):
        assert set(self.syn_scanned) == {"8.8.8.8/32"}
        assert set(self.ping_scanned) == {"8.8.8.0/24", "8.8.4.0/24"}
        assert self.syn_runs == 1
        assert self.ping_runs >= 1
        open_port_events = [e for e in events if e.type == "OPEN_TCP_PORT"]
        assert len(open_port_events) == 3
        assert {e.data for e in open_port_events} == {"8.8.8.8:443", "evilcorp.com:443", "www.evilcorp.com:443"}


class TestPortscanPingOnly(TestPortscan):
    modules_overrides = {"portscan"}
    config_overrides = {"modules": {"portscan": {"ports": "443", "wait": 1, "ping_only": True}}}

    targets = ["8.8.8.8/24", "8.8.4.4/24"]

    def check(self, module_test, events):
        assert set(self.syn_scanned) == set()
        assert set(self.ping_scanned) == {"8.8.8.0/24", "8.8.4.0/24"}
        assert self.syn_runs == 0
        assert self.ping_runs >= 1
        open_port_events = [e for e in events if e.type == "OPEN_TCP_PORT"]
        assert len(open_port_events) == 0
        ip_events = [e for e in events if e.type == "IP_ADDRESS"]
        assert len(ip_events) == 1
        assert {e.data for e in ip_events} == {"8.8.8.8"}
