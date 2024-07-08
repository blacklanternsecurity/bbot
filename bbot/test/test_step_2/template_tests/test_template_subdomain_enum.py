from ..module_tests.base import ModuleTestBase


class TestSubdomainEnum(ModuleTestBase):
    targets = ["blacklanternsecurity.com"]
    modules_overrides = []
    config_overrides = {"dns": {"minimal": False}, "scope": {"report_distance": 10}}
    dedup_strategy = "highest_parent"

    txt = [
        "www.blacklanternsecurity.com",
        "asdf.www.blacklanternsecurity.com",
        "test.asdf.www.blacklanternsecurity.com",
        "api.test.asdf.www.blacklanternsecurity.com",
    ]

    async def setup_after_prep(self, module_test):
        dns_mock = {
            "evilcorp.com": {"A": ["127.0.0.6"]},
            "blacklanternsecurity.com": {"A": ["127.0.0.5"]},
            "www.blacklanternsecurity.com": {"A": ["127.0.0.5"]},
            "asdf.www.blacklanternsecurity.com": {"A": ["127.0.0.5"]},
            "test.asdf.www.blacklanternsecurity.com": {"A": ["127.0.0.5"]},
            "api.test.asdf.www.blacklanternsecurity.com": {"A": ["127.0.0.5"]},
        }
        if self.txt:
            dns_mock["blacklanternsecurity.com"]["TXT"] = self.txt
        await module_test.mock_dns(dns_mock)

        # load subdomain enum template as module
        from bbot.modules.templates.subdomain_enum import subdomain_enum

        subdomain_enum_module = subdomain_enum(module_test.scan)

        self.queries = []

        async def mock_query(query):
            self.queries.append(query)

        subdomain_enum_module.query = mock_query
        subdomain_enum_module.dedup_strategy = self.dedup_strategy
        module_test.scan.modules["subdomain_enum"] = subdomain_enum_module

    def check(self, module_test, events):
        in_scope_dns_names = [e for e in events if e.type == "DNS_NAME" and e.scope_distance == 0]
        assert len(in_scope_dns_names) == 5
        assert 1 == len([e for e in in_scope_dns_names if e.data == "blacklanternsecurity.com"])
        assert 1 == len([e for e in in_scope_dns_names if e.data == "www.blacklanternsecurity.com"])
        assert 1 == len([e for e in in_scope_dns_names if e.data == "asdf.www.blacklanternsecurity.com"])
        assert 1 == len([e for e in in_scope_dns_names if e.data == "test.asdf.www.blacklanternsecurity.com"])
        assert 1 == len([e for e in in_scope_dns_names if e.data == "api.test.asdf.www.blacklanternsecurity.com"])
        assert len(self.queries) == 1
        assert self.queries[0] == "blacklanternsecurity.com"


class TestSubdomainEnumHighestParent(TestSubdomainEnum):
    targets = ["api.test.asdf.www.blacklanternsecurity.com", "evilcorp.com"]
    whitelist = ["www.blacklanternsecurity.com"]
    modules_overrides = ["speculate"]
    dedup_strategy = "highest_parent"
    txt = None

    def check(self, module_test, events):
        in_scope_dns_names = [e for e in events if e.type == "DNS_NAME" and e.scope_distance == 0]
        distance_1_dns_names = [e for e in events if e.type == "DNS_NAME" and e.scope_distance == 1]
        assert len(in_scope_dns_names) == 4
        assert 1 == len([e for e in in_scope_dns_names if e.data == "www.blacklanternsecurity.com"])
        assert 1 == len([e for e in in_scope_dns_names if e.data == "asdf.www.blacklanternsecurity.com"])
        assert 1 == len([e for e in in_scope_dns_names if e.data == "test.asdf.www.blacklanternsecurity.com"])
        assert 1 == len([e for e in in_scope_dns_names if e.data == "api.test.asdf.www.blacklanternsecurity.com"])
        assert len(distance_1_dns_names) == 2
        assert 1 == len([e for e in distance_1_dns_names if e.data == "evilcorp.com"])
        assert 1 == len([e for e in distance_1_dns_names if e.data == "blacklanternsecurity.com"])
        assert len(self.queries) == 1
        assert self.queries[0] == "www.blacklanternsecurity.com"


class TestSubdomainEnumLowestParent(TestSubdomainEnumHighestParent):
    dedup_strategy = "lowest_parent"

    def check(self, module_test, events):
        assert set(self.queries) == {
            "test.asdf.www.blacklanternsecurity.com",
            "asdf.www.blacklanternsecurity.com",
            "www.blacklanternsecurity.com",
        }
