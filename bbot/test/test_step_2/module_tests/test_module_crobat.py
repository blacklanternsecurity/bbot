from .base import ModuleTestBase


class TestCrobat(ModuleTestBase):
    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://sonar.omnisint.io/subdomains/blacklanternsecurity.com",
            json=["asdf.blacklanternsecurity.com"],
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"


class TestCrobatSetErrorState(TestCrobat):
    modules_overrides = ["crobat"]

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["crobat"].set_error_state()

    def check(self, module_test, events):
        assert module_test.scan.modules["crobat"].errored == True
