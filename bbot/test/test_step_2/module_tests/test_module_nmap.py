from .base import ModuleTestBase


class TestNmap(ModuleTestBase):
    targets = ["127.0.0.1"]
    config_overrides = {"modules": {"nmap": {"ports": "8888,8889"}}}

    def check(self, module_test, events):
        assert any(e.data == "127.0.0.1:8888" for e in events)
        assert not any(e.data == "127.0.0.1:8889" for e in events)
