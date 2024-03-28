from .base import ModuleTestBase


class TestSubdomains(ModuleTestBase):
    modules_overrides = ["subdomains", "subdomaincenter"]

    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url=f"https://api.subdomain.center/?domain=blacklanternsecurity.com",
            json=["asdfasdf.blacklanternsecurity.com", "zzzzzzzz.blacklanternsecurity.com"],
        )

    def check(self, module_test, events):
        sub_file = module_test.scan.home / "subdomains.txt"
        subdomains = set(open(sub_file).read().splitlines())
        assert subdomains == {"blacklanternsecurity.com"}


class TestSubdomainsUnresolved(TestSubdomains):
    config_overrides = {"modules": {"subdomains": {"include_unresolved": True}}}

    def check(self, module_test, events):
        sub_file = module_test.scan.home / "subdomains.txt"
        subdomains = set(open(sub_file).read().splitlines())
        assert subdomains == {
            "blacklanternsecurity.com",
            "asdfasdf.blacklanternsecurity.com",
            "zzzzzzzz.blacklanternsecurity.com",
        }
