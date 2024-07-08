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

        old_run_live = module_test.scan.helpers.run_live

        async def new_run_live(*command, check=False, text=True, **kwargs):
            if "massdns" in command[:2]:
                _input = [l async for l in kwargs["input"]]
                if "rrrr-test.blacklanternsecurity.com" in _input:
                    yield """{"name": "rrrr-test.blacklanternsecurity.com.", "type": "A", "class": "IN", "status": "NOERROR", "rx_ts": 1713974911725326170, "data": {"answers": [{"ttl": 86400, "type": "A", "class": "IN", "name": "rrrr-test.blacklanternsecurity.com.", "data": "1.2.3.4."}]}, "flags": ["rd", "ra"], "resolver": "195.226.187.130:53", "proto": "UDP"}"""
                if "rrrr-ffdsa.blacklanternsecurity.com" in _input:
                    yield """{"name": "rrrr-ffdsa.blacklanternsecurity.com.", "type": "A", "class": "IN", "status": "NOERROR", "rx_ts": 1713974911725326170, "data": {"answers": [{"ttl": 86400, "type": "A", "class": "IN", "name": "rrrr-ffdsa.blacklanternsecurity.com.", "data": "1.2.3.4."}]}, "flags": ["rd", "ra"], "resolver": "195.226.187.130:53", "proto": "UDP"}"""
                if "hmmmm.test2.blacklanternsecurity.com" in _input:
                    yield """{"name": "hmmmm.test2.blacklanternsecurity.com.", "type": "A", "class": "IN", "status": "NOERROR", "rx_ts": 1713974911725326170, "data": {"answers": [{"ttl": 86400, "type": "A", "class": "IN", "name": "hmmmm.test2.blacklanternsecurity.com.", "data": "1.2.3.4."}]}, "flags": ["rd", "ra"], "resolver": "195.226.187.130:53", "proto": "UDP"}"""
            else:
                async for _ in old_run_live(*command, check=False, text=True, **kwargs):
                    yield _

        module_test.monkeypatch.setattr(module_test.scan.helpers, "run_live", new_run_live)

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
        assert len(events) == 9
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
