from .base import ModuleTestBase


class TestEmail_Addresses(ModuleTestBase):
    modules_overrides = ["email_addresses", "emailformat"]

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://www.email-format.com/d/blacklanternsecurity.com/",
            text="<p>info@blacklanternsecurity.com</a>",
        )

    def check(self, module_test, events):
        sub_file = module_test.scan.home / "email_addresses.txt"
        email_addresses = set(open(sub_file).read().splitlines())
        assert email_addresses == {"info@blacklanternsecurity.com"}
