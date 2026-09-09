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
    seeds = ["api.test.asdf.www.blacklanternsecurity.com", "evilcorp.com"]
    targets = ["www.blacklanternsecurity.com"]
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

        # Passive subdomain enum templates operate on all seeds, even when
        # they are outside the explicit target_list.
        # we expect one query for the blacklantern scope and one for the unrelated evilcorp.com seed.
        assert set(self.queries) == {"www.blacklanternsecurity.com", "evilcorp.com"}


class TestSubdomainEnumLowestParent(TestSubdomainEnumHighestParent):
    dedup_strategy = "lowest_parent"

    def check(self, module_test, events):
        assert set(self.queries) == {
            "evilcorp.com",
            "test.asdf.www.blacklanternsecurity.com",
            "asdf.www.blacklanternsecurity.com",
            "www.blacklanternsecurity.com",
        }


class TestSubdomainEnumWildcardBaseline(ModuleTestBase):
    # oh walmart.cn why are you like this
    targets = ["walmart.cn"]
    seeds = ["www.walmart.cn"]
    modules_overrides = []
    config_overrides = {"dns": {"minimal": False}, "scope": {"report_distance": 10}, "omit_event_types": []}
    dedup_strategy = "highest_parent"

    dns_mock_data = {
        "walmart.cn": {"A": ["127.0.0.1"]},
        "www.walmart.cn": {"A": ["127.0.0.1"]},
        "test.walmart.cn": {"A": ["127.0.0.1"]},
    }

    async def setup_before_prep(self, module_test):
        self.queries = []

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(self.dns_mock_data)

        async def mock_query(query):
            self.queries.append(query)
            return ["walmart.cn", "www.walmart.cn", "test.walmart.cn", "asdf.walmart.cn"]

        # load subdomain enum template as module
        from bbot.modules.templates.subdomain_enum import subdomain_enum

        subdomain_enum_module = subdomain_enum(module_test.scan)
        await subdomain_enum_module.setup()

        subdomain_enum_module.query = mock_query
        subdomain_enum_module._name = "subdomain_enum"
        subdomain_enum_module.dedup_strategy = self.dedup_strategy
        module_test.scan.modules["subdomain_enum"] = subdomain_enum_module

    def check(self, module_test, events):
        assert self.queries == ["walmart.cn"]
        assert len(events) == 6
        # cross-parent (rdtype, child) dedup in DNSResolve.emit_dns_children collapses
        # the three walmart.cn->127.0.0.1 edges into a single IP_ADDRESS event
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and str(e.module) == "A" and e.scope_distance == 1
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "DNS_NAME"
                and e.data == "www.walmart.cn"
                and str(e.module) == "SEED"
                and e.scope_distance == 0
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "DNS_NAME"
                and e.data == "test.walmart.cn"
                and str(e.module) == "subdomain_enum"
                and e.scope_distance == 0
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "DNS_NAME_UNRESOLVED"
                and e.data == "asdf.walmart.cn"
                and str(e.module) == "subdomain_enum"
                and e.scope_distance == 0
            ]
        )


class TestSubdomainEnumWildcardDefense(TestSubdomainEnumWildcardBaseline):
    # oh walmart.cn why are you like this
    targets = ["walmart.cn"]
    seeds = ["walmart.cn"]
    modules_overrides = []
    config_overrides = {"dns": {"minimal": False}, "scope": {"report_distance": 10}}
    dedup_strategy = "highest_parent"

    dns_mock_data = {
        "walmart.cn": {"A": ["127.0.0.2"], "TXT": ['"asdf.walmart.cn"']},
        # wildcard: every *.walmart.cn resolves to an A record
        r"regex:.*\.walmart\.cn$": {"A": ["127.0.0.99"]},
    }

    async def setup_after_prep(self, module_test):
        import random

        await module_test.mock_dns(self.dns_mock_data)

        # Simulate walmart.cn's real-world behavior: random subdomains each
        # resolve to a *different* IP, so wildcard detection flags it as
        # POSSIBLE rather than TRUE. We monkey-patch _is_wildcard_zone to
        # return random IPs in its result set, mimicking the inconsistency.
        _original = module_test.scan.helpers.dns._is_wildcard_zone

        async def _random_wildcard_zone(host, rdtype):
            results, results_raw = await _original(host, rdtype)
            if results and host.endswith("walmart.cn"):
                # Replace the consistent mock IPs with random ones so the
                # wildcard detector sees them as POSSIBLE, not TRUE.
                results = {".".join(str(random.randint(1, 254)) for _ in range(4)) for _ in range(5)}
                results_raw = {str(ip) for ip in results}
            return results, results_raw

        module_test.scan.helpers.dns._is_wildcard_zone = _random_wildcard_zone

    def check(self, module_test, events):
        # no subdomain enum should happen on this domain!
        assert self.queries == []
        assert len(events) == 7
        assert 2 == len(
            [e for e in events if e.type == "IP_ADDRESS" and str(e.module) == "A" and e.scope_distance == 1]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "DNS_NAME"
                and e.data == "walmart.cn"
                and str(e.module) == "SEED"
                and e.scope_distance == 0
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "DNS_NAME"
                and e.data == "asdf.walmart.cn"
                and str(e.module) == "TXT"
                and e.scope_distance == 0
                and "wildcard-possible" in e.tags
                and "a-wildcard-possible" in e.tags
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "RAW_DNS_RECORD"
                and e.data == {"host": "walmart.cn", "type": "TXT", "answer": "asdf.walmart.cn"}
            ]
        )
