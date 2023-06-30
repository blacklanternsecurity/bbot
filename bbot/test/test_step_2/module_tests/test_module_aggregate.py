from .base import ModuleTestBase


class TestAggregate(ModuleTestBase):
    config_overrides = {"dns_resolution": True}

    def check(self, module_test, events):
        filename = next(module_test.scan.home.glob("scan-stats-table*.txt"))
        with open(filename) as f:
            assert "| A  " in f.read()
