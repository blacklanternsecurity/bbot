from .base import ModuleTestBase


class TestAffiliates(ModuleTestBase):
    targets = ["8.8.8.8"]
    config_overrides = {"dns_resolution": True}

    def check(self, module_test, events):
        filename = next(module_test.scan.home.glob("affiliates-table*.txt"))
        with open(filename) as f:
            assert "zdns.google" in f.read()
