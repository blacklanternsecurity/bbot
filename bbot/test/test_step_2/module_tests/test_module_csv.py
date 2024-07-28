from .base import ModuleTestBase


class TestCSV(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.5"]}})

    def check(self, module_test, events):
        csv_file = module_test.scan.home / "output.csv"
        context_data = f"Scan {module_test.scan.name} seeded with DNS_NAME: blacklanternsecurity.com"

        with open(csv_file) as f:
            data = f.read()
            assert "blacklanternsecurity.com,127.0.0.5,TARGET" in data
            assert context_data in data
