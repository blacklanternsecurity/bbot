from .base import ModuleTestBase


class TestMasscan(ModuleTestBase):
    targets = ["8.8.8.8/32"]
    scan_name = "test_masscan"
    config_overrides = {"modules": {"masscan": {"ports": "443", "wait": 1}}}
    masscan_config = """seed = 17230484647655100360
rate = 600       
shard = 1/1


# TARGET SELECTION (IP, PORTS, EXCLUDES)
ports = 
range = 9.8.7.6"""

    masscan_output = """[
{   "ip": "8.8.8.8",   "timestamp": "1680197558", "ports": [ {"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 54} ] }
]"""

    async def setup_after_prep(self, module_test):
        self.masscan_run = False

        async def run_masscan(command, *args, **kwargs):
            if "masscan" in command[:2]:
                for l in self.masscan_output.splitlines():
                    yield l
                self.masscan_run = True
            else:
                async for l in module_test.scan.helpers.run_live(command, *args, **kwargs):
                    yield l

        module_test.scan.modules["masscan"].masscan_config = self.masscan_config
        module_test.monkeypatch.setattr(module_test.scan.helpers, "run_live", run_masscan)

    def check(self, module_test, events):
        assert self.masscan_run == True
        assert any(e.type == "IP_ADDRESS" and e.data == "8.8.8.8" for e in events), "No IP_ADDRESS emitted"
        assert any(e.type == "OPEN_TCP_PORT" and e.data == "8.8.8.8:443" for e in events), "No OPEN_TCP_PORT emitted"


class TestMasscan1(TestMasscan):
    modules_overrides = ["masscan"]
    config_overrides = {"modules": {"masscan": {"ports": "443", "wait": 1, "use_cache": True}}}

    def check(self, module_test, events):
        assert self.masscan_run == False
        assert any(e.type == "IP_ADDRESS" and e.data == "8.8.8.8" for e in events), "No IP_ADDRESS emitted"
        assert any(e.type == "OPEN_TCP_PORT" and e.data == "8.8.8.8:443" for e in events), "No OPEN_TCP_PORT emitted"
