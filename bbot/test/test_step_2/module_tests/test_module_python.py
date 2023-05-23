from .base import ModuleTestBase


class TestPython(ModuleTestBase):
    def check(self, module_test, events):
        assert any(e.data == "blacklanternsecurity.com" for e in events)
