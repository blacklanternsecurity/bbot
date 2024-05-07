from .base import ModuleTestBase


class TestCSV(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.5"]}})

    def check(self, module_test, events):
        csv_file = module_test.scan.home / "output.csv"
        with open(csv_file) as f:
            assert "blacklanternsecurity.com,127.0.0.5,TARGET" in f.read()
