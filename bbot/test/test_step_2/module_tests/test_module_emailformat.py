from .base import ModuleTestBase


class TestEmailFormat(ModuleTestBase):
    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://www.email-format.com/d/blacklanternsecurity.com/",
            text="<p>info@blacklanternsecurity.com</a>",
        )

    def check(self, module_test, events):
        assert any(e.data == "info@blacklanternsecurity.com" for e in events), "Failed to detect email"
