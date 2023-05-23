from .base import ModuleTestBase


class TestCSV(ModuleTestBase):
    def check(self, module_test, events):
        csv_file = module_test.scan.home / "output.csv"
        with open(csv_file) as f:
            assert "DNS_NAME,blacklanternsecurity.com,,TARGET" in f.read()
