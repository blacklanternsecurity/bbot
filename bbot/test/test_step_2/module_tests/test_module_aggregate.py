from .base import ModuleTestBase


class TestAggregate(ModuleTestBase):
    config_overrides = {"dns_resolution": True, "scope_report_distance": 1}

    async def setup_before_prep(self, module_test):
        module_test.scan.helpers.dns.mock_dns({("blacklanternsecurity.com", "A"): "1.2.3.4"})

    def check(self, module_test, events):
        filename = next(module_test.scan.home.glob("scan-stats-table*.txt"))
        with open(filename) as f:
            assert "| A  " in f.read()
