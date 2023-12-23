from .base import ModuleTestBase


class TestEmais(ModuleTestBase):
    modules_overrides = ["emails", "emailformat", "skymem"]

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://www.email-format.com/d/blacklanternsecurity.com/",
            text="<p>info@blacklanternsecurity.com</p>",
        )
        module_test.httpx_mock.add_response(
            url="https://www.skymem.info/srch?q=blacklanternsecurity.com",
            text="<p>info@blacklanternsecurity.com</p>",
        )

    def check(self, module_test, events):
        assert 2 == len([e for e in events if e.data == "info@blacklanternsecurity.com"])
        email_file = module_test.scan.home / "emails.txt"
        emails = open(email_file).read().splitlines()
        # make sure deduping works as intended
        assert len(emails) == 1
        assert set(emails) == {"info@blacklanternsecurity.com"}
