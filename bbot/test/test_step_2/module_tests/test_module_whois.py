from .base import ModuleTestBase

from bbot.test.whois_samples import whois_sample

DNS_MOCK = {
    "github.com": {"A": ["127.0.0.88"]},
    "api.github.com": {"A": ["127.0.0.88"]},
    "namecheap.com": {"A": ["127.0.0.89"]},
    # affiliate: www.github.com is hosted on wikipedia's infrastructure
    "www.github.com": {"A": ["127.0.0.88"], "CNAME": ["edge.wikipedia.org"]},
    "edge.wikipedia.org": {"A": ["127.0.0.90"]},
}


def mock_whois(module_test):
    """Serve captured WHOIS text instead of querying port 43, recording each query."""
    import whois
    from whois.parser import WhoisEntry
    from baddns.lib.whoismanager import WhoisManager

    queries = []

    def fake_whois(domain, **kwargs):
        queries.append(domain)
        return WhoisEntry.load(domain, whois_sample(domain))

    WhoisManager.clear_cache()
    module_test.monkeypatch.setattr(whois, "whois", fake_whois)
    return queries


def whois_metadata(event):
    return {host: meta["whois"] for host, meta in event.host_metadata.items() if "whois" in meta}


class TestWhois(ModuleTestBase):
    # host.local (no public suffix) and co.uk (a bare public suffix) have no registrable domain
    targets = ["github.com", "www.github.com", "api.github.com", "namecheap.com", "host.local", "co.uk"]
    # non-minimal DNS so the CNAME to the affiliate domain gets emitted
    config_overrides = {"dns": {"minimal": False}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(DNS_MOCK)
        self.queries = mock_whois(module_test)

    def check(self, module_test, events):
        dns_names = {e.data: e for e in events if e.type == "DNS_NAME"}

        # enrichment has to land before the event is distributed, so it must be an intercept module
        assert module_test.scan.modules["whois"]._intercept

        # one query per registrable domain, no matter how many subdomains carry it
        assert sorted(self.queries) == ["github.com", "namecheap.com"], self.queries

        # every in-scope name under a domain is enriched, keyed by the registrable domain
        for host in ("github.com", "www.github.com", "api.github.com"):
            assert whois_metadata(dns_names[host]).keys() == {"github.com"}, host
        github = whois_metadata(dns_names["github.com"])["github.com"]
        assert github["registrar"] == "MarkMonitor, Inc."
        assert github["registrant_org"] == "GitHub, Inc."
        assert github["expires"] == "2028-10-09T18:20:50Z"
        # the raw WHOIS text is far too big to ride along on every event
        assert "raw" not in github

        namecheap = whois_metadata(dns_names["namecheap.com"])["namecheap.com"]
        assert namecheap["registrant_redacted"] is True
        assert "registrant_org" not in namecheap

        # no registrable domain, so nothing to look up
        assert whois_metadata(dns_names["host.local"]) == {}
        assert whois_metadata(dns_names["co.uk"]) == {}

        # out of scope: enrichment stays in scope so a blocking lookup can't run away with the scan
        affiliate = dns_names["edge.wikipedia.org"]
        assert affiliate.scope_distance > 0
        assert whois_metadata(affiliate) == {}


class TestWhoisDisabledByDefault(ModuleTestBase):
    module_name = "whois"
    modules_overrides = []
    targets = ["github.com"]

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(DNS_MOCK)
        self.queries = mock_whois(module_test)

    def check(self, module_test, events):
        assert "whois" not in module_test.scan.modules
        assert self.queries == []
        assert all(whois_metadata(e) == {} for e in events if e.host)
