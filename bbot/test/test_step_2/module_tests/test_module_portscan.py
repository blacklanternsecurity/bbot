from .base import ModuleTestBase


class TestPortscan(ModuleTestBase):
    targets = ["8.8.8.8/32"]
    scan_name = "test_portscan"
    config_overrides = {"modules": {"portscan": {"ports": "443", "wait": 1}}}

    masscan_output = """{   "ip": "8.8.8.8",   "timestamp": "1680197558", "ports": [ {"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 54} ] }"""

    async def setup_after_prep(self, module_test):
        self.masscan_run = False

        async def run_masscan(command, *args, **kwargs):
            if "masscan" in command[:2]:
                targets = open(command[11]).read().splitlines()
                yield "["
                for l in self.masscan_output.splitlines():
                    if "8.8.8.8/32" in targets:
                        yield self.masscan_output
                yield "]"
                self.masscan_run = True
            else:
                async for l in module_test.scan.helpers.run_live(command, *args, **kwargs):
                    yield l

        module_test.monkeypatch.setattr(module_test.scan.helpers, "run_live", run_masscan)

    def check(self, module_test, events):
        assert self.masscan_run == True
        assert any(e.type == "IP_ADDRESS" and e.data == "8.8.8.8" for e in events), "No IP_ADDRESS emitted"
        assert any(e.type == "OPEN_TCP_PORT" and e.data == "8.8.8.8:443" for e in events), "No OPEN_TCP_PORT emitted"
