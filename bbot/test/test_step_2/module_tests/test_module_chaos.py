from .base import ModuleTestBase


class TestChaos(ModuleTestBase):
    config_overrides = {"modules": {"chaos": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://dns.projectdiscovery.io/dns/example.com",
            match_headers={"Authorization": "asdf"},
            json={"domain": "example.com", "subdomains": 65},
        )
        module_test.blasthttp_mock.add_response(
            url="https://dns.projectdiscovery.io/dns/blacklanternsecurity.com/subdomains",
            match_headers={"Authorization": "asdf"},
            json={
                "domain": "blacklanternsecurity.com",
                "subdomains": [
                    "*.asdf.cloud",
                ],
            },
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.cloud.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"


class TestChaosFloodCollapse(ModuleTestBase):
    """Chaos sometimes returns hundreds of thousands of children under a single
    parent (typically ISP PTR explosions). Verify two behaviors:

      1. Names whose leading segments look like IPv4 octets (dotted or
         hyphenated) are filtered out as obvious PTR garbage.
      2. When a parent still has more children than the cap, the children are
         dropped and the parent is emitted on its own — letting bbot's normal
         DNS wildcard detection decide whether it's actually wildcard.
    """

    modules_overrides = ["chaos"]
    config_overrides = {"modules": {"chaos": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        flood = []
        # PTR junk that should be dropped by the IP-octet regex before it ever
        # contributes to a parent's child count.
        ptr_junk = [
            "001.106.103.218.static",  # dotted leading octets, with leading zero
            "192.168.1.1.static",  # dotted leading octets
            "203.0.113.7.customer",  # dotted leading octets
            "000-1-246-220.static",  # hyphenated leading octets, leading zero
            "10-20-30-40.static",  # hyphenated leading octets
            "42-98-224-32.cust",  # hyphenated leading octets
        ]
        flood.extend(ptr_junk)
        # 400 fake siblings under one parent (above the cap=300) — should
        # collapse to just the parent.
        flood.extend(f"host{i}.bigparent" for i in range(400))
        # A normal subdomain under a different parent — should pass through.
        flood.append("realone.normalparent")
        # Date-prefixed name that should NOT be caught by the PTR filter.
        flood.append("2024.01.15.report.bigparent")

        module_test.blasthttp_mock.add_response(
            url="https://dns.projectdiscovery.io/dns/example.com",
            match_headers={"Authorization": "asdf"},
            json={"domain": "example.com", "subdomains": 65},
        )
        module_test.blasthttp_mock.add_response(
            url="https://dns.projectdiscovery.io/dns/blacklanternsecurity.com/subdomains",
            match_headers={"Authorization": "asdf"},
            json={"domain": "blacklanternsecurity.com", "subdomains": flood},
        )

    def check(self, module_test, events):
        emitted = [e.data for e in events if e.module and getattr(e.module, "name", "") == "chaos"]

        # 400 flooded children -> dropped; parent emitted instead
        assert "bigparent.blacklanternsecurity.com" in emitted, (
            f"Expected parent to be emitted when children exceed cap; got {emitted}"
        )
        assert not any(d.startswith("host") for d in emitted), (
            f"Flooded children should have been dropped; got {emitted}"
        )

        # Normal sibling under an uncapped parent passes through
        assert "realone.normalparent.blacklanternsecurity.com" in emitted, (
            f"Real subdomain under uncapped parent should be emitted; got {emitted}"
        )

        # Every PTR-style leading-IP-octet name is filtered before reaching the cap
        ptr_fragments = [
            "001.106.103.218",
            "192.168.1.1",
            "203.0.113.7",
            "000-1-246-220",
            "10-20-30-40",
            "42-98-224-32",
        ]
        for frag in ptr_fragments:
            assert not any(frag in d for d in emitted), (
                f"PTR-style name containing {frag!r} should have been filtered; got {emitted}"
            )

        # Date-prefixed names must NOT be filtered (only 4-group IPv4 patterns are)
        assert "2024.01.15.report.bigparent.blacklanternsecurity.com" in emitted, (
            f"Date-prefixed subdomain should survive PTR filter; got {emitted}"
        )


class TestChaosApexFlood(ModuleTestBase):
    """>300 subdomains directly under the queried apex must not be collapsed."""

    modules_overrides = ["chaos"]
    config_overrides = {"modules": {"chaos": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://dns.projectdiscovery.io/dns/example.com",
            match_headers={"Authorization": "asdf"},
            json={"domain": "example.com", "subdomains": 65},
        )
        flood = [f"svc{i}" for i in range(400)] + ["realsub.cluster"]
        module_test.blasthttp_mock.add_response(
            url="https://dns.projectdiscovery.io/dns/blacklanternsecurity.com/subdomains",
            match_headers={"Authorization": "asdf"},
            json={"domain": "blacklanternsecurity.com", "subdomains": flood},
        )

    def check(self, module_test, events):
        assert module_test.scan.modules["chaos"].errored is False
        emitted = [e.data for e in events if e.module and getattr(e.module, "name", "") == "chaos"]
        assert any(d.startswith("svc") for d in emitted), (
            f"Direct-apex subdomains should not be collapsed; got {emitted}"
        )
        assert "realsub.cluster.blacklanternsecurity.com" in emitted, f"Nested subdomain should survive; got {emitted}"


class TestChaosDuplicateInflation(ModuleTestBase):
    """Duplicate entries from chaos must not inflate the per-parent cap count.

    A parent with fewer unique children than PER_PARENT_CAP must not be
    collapsed just because chaos returned the same names multiple times.
    """

    modules_overrides = ["chaos"]
    config_overrides = {"modules": {"chaos": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://dns.projectdiscovery.io/dns/example.com",
            match_headers={"Authorization": "asdf"},
            json={"domain": "example.com", "subdomains": 65},
        )
        # 250 unique children (under cap=300), each sent twice -> 500 raw entries.
        # Cap must count unique, not raw, so none should be collapsed.
        uniq = [f"svc{i}.cluster" for i in range(250)]
        flood = uniq + uniq
        module_test.blasthttp_mock.add_response(
            url="https://dns.projectdiscovery.io/dns/blacklanternsecurity.com/subdomains",
            match_headers={"Authorization": "asdf"},
            json={"domain": "blacklanternsecurity.com", "subdomains": flood},
        )

    def check(self, module_test, events):
        assert module_test.scan.modules["chaos"].errored is False
        emitted = [e.data for e in events if e.module and getattr(e.module, "name", "") == "chaos"]
        svc = [d for d in emitted if d.startswith("svc")]
        assert len(svc) == 250, (
            f"all 250 unique children should survive (cap must count unique, not duplicates); got {len(svc)}"
        )
        assert "cluster.blacklanternsecurity.com" not in emitted, (
            "parent must not be collapsed when unique child count is under the cap"
        )
