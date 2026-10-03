from .base import ModuleTestBase

from bbot.test.whois_samples import whois_sample


def mock_whois(module_test, samples):
    """Serve captured WHOIS text instead of querying port 43, recording each query."""
    queries = []
    helper = module_test.scan.helpers.whois

    async def query(domain):
        queries.append(domain)
        return samples.get(domain)

    module_test.monkeypatch.setattr(helper, "query", query)
    return queries


class TestWhois(ModuleTestBase):
    # host.local (no public suffix) and co.uk (a bare public suffix) have no registrable domain
    targets = ["github.com", "www.github.com", "api.github.com", "namecheap.com", "host.local", "co.uk"]
    # non-minimal DNS so the CNAME to the affiliate domain gets emitted
    config_overrides = {"dns": {"minimal": False}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "github.com": {"A": ["127.0.0.88"]},
                "api.github.com": {"A": ["127.0.0.88"]},
                "namecheap.com": {"A": ["127.0.0.89"]},
                # affiliate: www.github.com is hosted on wikipedia's infrastructure
                "www.github.com": {"A": ["127.0.0.88"], "CNAME": ["edge.wikipedia.org"]},
                "edge.wikipedia.org": {"A": ["127.0.0.90"]},
            }
        )
        self.queries = mock_whois(
            module_test, {d: whois_sample(d) for d in ("github.com", "namecheap.com", "wikipedia.org")}
        )

    def check(self, module_test, events):
        registrations = [e for e in events if e.type == "DOMAIN_REGISTRATION"]
        hosts = sorted(e.data["host"] for e in registrations)
        # exactly one per registrable domain, even though github.com has several subdomains
        assert hosts == ["github.com", "namecheap.com", "wikipedia.org"], hosts
        # each domain is queried once, and names without a registrable domain never are
        assert sorted(self.queries) == ["github.com", "namecheap.com", "wikipedia.org"], self.queries
        assert any(e.type == "DNS_NAME" and e.data == "host.local" for e in events)
        assert any(e.type == "DNS_NAME" and e.data == "co.uk" for e in events)

        github = next(e for e in registrations if e.data["host"] == "github.com")
        assert github.data["registrar"] == "MarkMonitor, Inc."
        assert github.data["registrant_org"] == "GitHub, Inc."
        assert github.data["expires"] == "2028-10-09T18:20:50Z"
        assert "raw" not in github.data
        assert github.scope_distance == 0
        assert github.pretty_string == "github.com (MarkMonitor, Inc.)"
        assert 'queried WHOIS for "github.com"' in github.discovery_context

        namecheap = next(e for e in registrations if e.data["host"] == "namecheap.com")
        assert namecheap.data["registrant_redacted"] is True
        assert "registrant_org" not in namecheap.data

        # affiliate registrations reach output
        wikipedia = next(e for e in registrations if e.data["host"] == "wikipedia.org")
        assert wikipedia.data["registrar"] == "MarkMonitor Inc."
        assert wikipedia.scope_distance > 0
        assert not wikipedia._internal


class TestWhoisRawAndFailure(ModuleTestBase):
    module_name = "whois"
    targets = ["github.com", "evilcorp.com"]
    config_overrides = {"modules": {"whois": {"include_raw": True}}}

    async def setup_after_prep(self, module_test):
        mock_whois(module_test, {"github.com": whois_sample("github.com")})

    def check(self, module_test, events):
        registrations = [e for e in events if e.type == "DOMAIN_REGISTRATION"]
        assert [e.data["host"] for e in registrations] == ["github.com"]
        assert "Registrar IANA ID: 292" in registrations[0].data["raw"]
