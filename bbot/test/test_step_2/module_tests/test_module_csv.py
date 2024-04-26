from .base import ModuleTestBase


class TestCSV(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({})

    def check(self, module_test, events):
        csv_file = module_test.scan.home / "output.csv"
        with open(csv_file) as f:
            assert "DNS_NAME,blacklanternsecurity.com,,TARGET" in f.read()
