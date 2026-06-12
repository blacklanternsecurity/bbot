from .base import ModuleTestBase


class TestDNSCommonSRV(ModuleTestBase):
    seeds = ["media.www.test.api.blacklanternsecurity.com"]
    targets = ["blacklanternsecurity.com"]
    modules_overrides = ["dnscommonsrv", "speculate"]
    config_overrides = {"dns": {"minimal": False}}

    async def setup_after_prep(self, module_test):
        old_run_live = module_test.scan.helpers.run_live

        async def new_run_live(*command, check=False, text=True, **kwargs):
            if "massdns" in command[:2]:
                _input = [l async for l in kwargs["input"]]
                if "_ldap._tcp.gc._msdcs.blacklanternsecurity.com" in _input:
                    yield """{"name":"_ldap._tcp.gc._msdcs.blacklanternsecurity.com.","type":"SRV","class":"IN","status":"NOERROR","rx_ts":1713974911725326170,"data":{"answers":[{"ttl":86400,"type":"SRV","class":"IN","name":"_ldap._tcp.gc._msdcs.blacklanternsecurity.com.","data":"10 10 1720 asdf.blacklanternsecurity.com."},{"ttl":86400,"type":"SRV","class":"IN","name":"_ldap._tcp.gc._msdcs.blacklanternsecurity.com.","data":"10 10 1720 asdf.blacklanternsecurity.com."}]},"flags":["rd","ra"],"resolver":"195.226.187.130:53","proto":"UDP"}"""
                if "_ldap._tcp.gc._msdcs.api.blacklanternsecurity.com" in _input:
                    yield """{"name":"_ldap._tcp.gc._msdcs.api.blacklanternsecurity.com.","type":"SRV","class":"IN","status":"NOERROR","rx_ts":1713974911725326170,"data":{"answers":[{"ttl":86400,"type":"SRV","class":"IN","name":"_ldap._tcp.gc._msdcs.api.blacklanternsecurity.com.","data":"10 10 1720 asdf.blacklanternsecurity.com."},{"ttl":86400,"type":"SRV","class":"IN","name":"_ldap._tcp.gc._msdcs.blacklanternsecurity.com.","data":"10 10 1720 asdf.blacklanternsecurity.com."}]},"flags":["rd","ra"],"resolver":"195.226.187.130:53","proto":"UDP"}"""
                if "_ldap._tcp.gc._msdcs.test.api.blacklanternsecurity.com" in _input:
                    yield """{"name":"_ldap._tcp.gc._msdcs.test.api.blacklanternsecurity.com.","type":"SRV","class":"IN","status":"NOERROR","rx_ts":1713974911725326170,"data":{"answers":[{"ttl":86400,"type":"SRV","class":"IN","name":"_ldap._tcp.gc._msdcs.test.api.blacklanternsecurity.com.","data":"10 10 1720 asdf.blacklanternsecurity.com."},{"ttl":86400,"type":"SRV","class":"IN","name":"_ldap._tcp.gc._msdcs.blacklanternsecurity.com.","data":"10 10 1720 asdf.blacklanternsecurity.com."}]},"flags":["rd","ra"],"resolver":"195.226.187.130:53","proto":"UDP"}"""
                if "_ldap._tcp.gc._msdcs.www.test.api.blacklanternsecurity.com" in _input:
                    yield """{"name":"_ldap._tcp.gc._msdcs.www.test.api.blacklanternsecurity.com.","type":"SRV","class":"IN","status":"NOERROR","rx_ts":1713974911725326170,"data":{"answers":[{"ttl":86400,"type":"SRV","class":"IN","name":"_ldap._tcp.gc._msdcs.www.test.api.blacklanternsecurity.com.","data":"10 10 1720 asdf.blacklanternsecurity.com."},{"ttl":86400,"type":"SRV","class":"IN","name":"_ldap._tcp.gc._msdcs.blacklanternsecurity.com.","data":"10 10 1720 asdf.blacklanternsecurity.com."}]},"flags":["rd","ra"],"resolver":"195.226.187.130:53","proto":"UDP"}"""
                if "_ldap._tcp.gc._msdcs.media.www.test.api.blacklanternsecurity.com" in _input:
                    yield """{"name":"_ldap._tcp.gc._msdcs.www.test.api.blacklanternsecurity.com.","type":"SRV","class":"IN","status":"NOERROR","rx_ts":1713974911725326170,"data":{"answers":[{"ttl":86400,"type":"SRV","class":"IN","name":"_ldap._tcp.gc._msdcs.media.www.test.api.blacklanternsecurity.com.","data":"10 10 1720 asdf.blacklanternsecurity.com."},{"ttl":86400,"type":"SRV","class":"IN","name":"_ldap._tcp.gc._msdcs.blacklanternsecurity.com.","data":"10 10 1720 asdf.blacklanternsecurity.com."}]},"flags":["rd","ra"],"resolver":"195.226.187.130:53","proto":"UDP"}"""
            else:
                async for _ in old_run_live(*command, check=False, text=True, **kwargs):
                    yield _

        module_test.monkeypatch.setattr(module_test.scan.helpers, "run_live", new_run_live)

        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "api.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "test.api.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "www.test.api.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "media.www.test.api.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "_ldap._tcp.gc._msdcs.blacklanternsecurity.com": {"SRV": ["0 100 3268 asdf.blacklanternsecurity.com"]},
                "_ldap._tcp.gc._msdcs.api.blacklanternsecurity.com": {
                    "SRV": ["0 100 3268 asdf.blacklanternsecurity.com"]
                },
                "_ldap._tcp.gc._msdcs.test.api.blacklanternsecurity.com": {
                    "SRV": ["0 100 3268 asdf.blacklanternsecurity.com"]
                },
                "_ldap._tcp.gc._msdcs.www.test.api.blacklanternsecurity.com": {
                    "SRV": ["0 100 3268 asdf.blacklanternsecurity.com"]
                },
                "_ldap._tcp.gc._msdcs.media.www.test.api.blacklanternsecurity.com": {
                    "SRV": ["0 100 3268 asdf.blacklanternsecurity.com"]
                },
                "asdf.blacklanternsecurity.com": {"A": ["1.2.3.5"]},
                "_msdcs.api.blacklanternsecurity.com": {"A": ["1.2.3.5"]},
            }
        )

    def check(self, module_test, events):
        assert len(events) == 20
        assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "blacklanternsecurity.com"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "DNS_NAME"
                and e.data == "_ldap._tcp.gc._msdcs.blacklanternsecurity.com"
                and str(e.module) == "dnscommonsrv"
            ]
        ), "Failed to detect subdomain 1"
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "DNS_NAME"
                and e.data == "_ldap._tcp.gc._msdcs.api.blacklanternsecurity.com"
                and str(e.module) == "dnscommonsrv"
            ]
        ), "Failed to detect subdomain 2"
        # asdf.blacklanternsecurity.com is in-scope shared infrastructure: the SRV target of two
        # different in-scope _ldap records. both parent->child edges are preserved for graph output
        # (the second as a graph-important re-emission), so it produces two DNS_NAME events.
        asdf_events = [e for e in events if e.type == "DNS_NAME" and e.data == "asdf.blacklanternsecurity.com"]
        assert 2 == len(asdf_events), "Failed to detect subdomain 3"
        assert {str(e.parent.data) for e in asdf_events} == {
            "_ldap._tcp.gc._msdcs.blacklanternsecurity.com",
            "_ldap._tcp.gc._msdcs.api.blacklanternsecurity.com",
        }, "in-scope shared SRV target should keep both cross-parent edges"
        assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "api.blacklanternsecurity.com"]), (
            "Failed to detect subdomain 4"
        )
        assert 1 == len(
            [e for e in events if e.type == "DNS_NAME" and e.data == "test.api.blacklanternsecurity.com"]
        ), "Failed to detect subdomain 5"
        assert 1 == len(
            [e for e in events if e.type == "DNS_NAME" and e.data == "_msdcs.api.blacklanternsecurity.com"]
        ), "Failed to detect subdomain 5"
        assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "blacklanternsecurity.com"]), (
            "Failed to detect main domain"
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "RAW_DNS_RECORD"
                and e.data["host"] == "_ldap._tcp.gc._msdcs.api.blacklanternsecurity.com"
                and e.data["answer"] == "0 100 3268 asdf.blacklanternsecurity.com"
            ]
        ), "Failed to emit RAW_DNS_RECORD for _ldap._tcp.gc._msdcs.api.blacklanternsecurity.com"
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "RAW_DNS_RECORD"
                and e.data["host"] == "_ldap._tcp.gc._msdcs.blacklanternsecurity.com"
                and e.data["answer"] == "0 100 3268 asdf.blacklanternsecurity.com"
            ]
        ), "Failed to emit RAW_DNS_RECORD for _ldap._tcp.gc._msdcs.blacklanternsecurity.com"
        assert 2 == len([e for e in events if e.type == "RAW_DNS_RECORD"])
        assert 10 == len([e for e in events if e.type == "DNS_NAME"])
        assert 5 == len([e for e in events if e.type == "DNS_NAME_UNRESOLVED"])
        assert 5 == len([e for e in events if e.type == "DNS_NAME_UNRESOLVED" and str(e.module) == "speculate"])


class TestDNSCommonSRVMutationFilterDefault(ModuleTestBase):
    """By default (recursive_mutations=False) mutation-tagged events are rejected."""

    module_name = "dnscommonsrv"
    targets = ["blacklanternsecurity.com"]

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["1.2.3.4"]}})
        event = module_test.scan.make_event(
            "mut.blacklanternsecurity.com",
            "DNS_NAME",
            parent=module_test.scan.root_event,
            tags=["mutation-1"],
        )
        event.scope_distance = 0
        result, reason = await module_test.module.filter_event(event)
        assert result is False
        assert reason == "event was discovered by dnsbrute_mutations and recursive_mutations is False"

    def check(self, module_test, events):
        pass


class TestDNSCommonSRVRecursiveMutations(ModuleTestBase):
    """With recursive_mutations=True the mutation tag no longer rejects the event."""

    module_name = "dnscommonsrv"
    targets = ["blacklanternsecurity.com"]
    config_overrides = {"modules": {"dnscommonsrv": {"recursive_mutations": True}}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["1.2.3.4"]}})
        event = module_test.scan.make_event(
            "mut.blacklanternsecurity.com",
            "DNS_NAME",
            parent=module_test.scan.root_event,
            tags=["mutation-1"],
        )
        event.scope_distance = 0
        result = await module_test.module.filter_event(event)
        assert result is True

    def check(self, module_test, events):
        pass
