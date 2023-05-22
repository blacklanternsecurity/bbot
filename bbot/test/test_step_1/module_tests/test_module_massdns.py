from .base import ModuleTestBase, tempwordlist


class TestMassdns(ModuleTestBase):
    subdomain_wordlist = tempwordlist(["www", "asdf"])
    config_overrides = {"modules": {"massdns": {"wordlist": str(subdomain_wordlist)}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://raw.githubusercontent.com/blacklanternsecurity/public-dns-servers/master/nameservers.txt",
            text="8.8.8.8\n8.8.4.4\n1.1.1.1",
        )

    def check(self, module_test, events):
        assert any(e.data == "www.blacklanternsecurity.com" for e in events)
        assert not any(e.data == "asdf.blacklanternsecurity.com" for e in events)
