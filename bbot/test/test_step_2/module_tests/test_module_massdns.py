from .base import ModuleTestBase, tempwordlist


class TestMassdns(ModuleTestBase):
    subdomain_wordlist = tempwordlist(["www", "asdf"])
    config_overrides = {"modules": {"massdns": {"wordlist": str(subdomain_wordlist)}}}

    def check(self, module_test, events):
        assert any(e.data == "www.blacklanternsecurity.com" for e in events)
        assert not any(e.data == "asdf.blacklanternsecurity.com" for e in events)
