from .base import ModuleTestBase


class TestGeneric_SSRF(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]

    # PAUL TODO
    def check(self, module_test, events):
        pass
