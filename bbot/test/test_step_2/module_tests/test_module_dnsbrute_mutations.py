from .base import ModuleTestBase


class TestDnsbrute_mutations(ModuleTestBase):
    targets = [
        "blacklanternsecurity.com",
        "rrrr.blacklanternsecurity.com",
        "asdff-ffdsa.blacklanternsecurity.com",
        "hmmmm.test1.blacklanternsecurity.com",
        "uuuuu.test2.blacklanternsecurity.com",
    ]

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                # targets
                "rrrr.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "asdff-ffdsa.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "hmmmm.test1.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "uuuuu.test2.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                # devops mutation
                "rrrr-test.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                # target-specific dns mutation
                "rrrr-ffdsa.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                # subdomain from one subdomain on a different subdomain
                "hmmmm.test2.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
            }
        )

    def check(self, module_test, events):
        assert len(events) == 10
        assert 1 == len(
            [
                e
                for e in events
                if e.data == "rrrr-test.blacklanternsecurity.com" and str(e.module) == "dnsbrute_mutations"
            ]
        ), "Failed to find devops mutation (word_cloud)"
        assert 1 == len(
            [
                e
                for e in events
                if e.data == "rrrr-ffdsa.blacklanternsecurity.com" and str(e.module) == "dnsbrute_mutations"
            ]
        ), "Failed to find target-specific mutation (word_cloud.dns_mutator)"
        assert 1 == len(
            [
                e
                for e in events
                if e.data == "hmmmm.test2.blacklanternsecurity.com" and str(e.module) == "dnsbrute_mutations"
            ]
        ), "Failed to find subdomain taken from another subdomain"
