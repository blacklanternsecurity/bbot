from .base import ModuleTestBase


class TestEmais(ModuleTestBase):
    modules_overrides = ["emails", "emailformat"]

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://www.email-format.com/d/blacklanternsecurity.com/",
            text="<p>info@blacklanternsecurity.com</a>",
        )

    def check(self, module_test, events):
        sub_file = module_test.scan.home / "emails.txt"
        emails = set(open(sub_file).read().splitlines())
        assert emails == {"info@blacklanternsecurity.com"}
