from .base import ModuleTestBase


class TestTXT(ModuleTestBase):
    def check(self, module_test, events):
        txt_file = module_test.scan.home / "output.txt"
        with open(txt_file) as f:
            assert f.read().startswith("[SCAN]")
