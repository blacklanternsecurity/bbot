from .base import ModuleTestBase

from bbot.test.mock_blasthttp import MockResponse
from bbot.test.rdap_samples import rdap_sample
from bbot.core.helpers.rdap import RDAP_BOOTSTRAP_URL


def count_calls(mock, url, response):
    """Mock `url` with `response`, recording each request."""
    calls = []

    def callback(request):
        calls.append(request.url)
        return response

    mock.add_callback(callback, url=url)
    return calls


def spy_lookups(module_test):
    """Record the domain of every RDAP lookup the scan makes."""
    rdap_helper = module_test.scan.helpers.rdap
    lookups = []
    lookup = rdap_helper.lookup

    async def _lookup(domain, *args, **kwargs):
        lookups.append(domain)
        return await lookup(domain, *args, **kwargs)

    rdap_helper.lookup = _lookup
    return lookups


class TestRdap(ModuleTestBase):
    # host.local (no public suffix) and co.uk (a bare public suffix) have no registrable domain
    targets = ["github.com", "www.github.com", "api.github.com", "bbc.co.uk", "host.local", "co.uk"]
    # non-minimal DNS so the CNAME to the affiliate domain gets emitted
    config_overrides = {"dns": {"minimal": False}, "modules": {"rdap": {"server_interval": 0}}}

    registry_urls = {
        "github.com": "https://rdap.verisign.com/com/v1/domain/github.com",
        "bbc.co.uk": "https://rdap.nominet.uk/uk/domain/bbc.co.uk",
        "wikipedia.org": "https://rdap.publicinterestregistry.org/rdap/domain/wikipedia.org",
    }

    async def setup_before_prep(self, module_test):
        module_test.scan.helpers.cache_filename(RDAP_BOOTSTRAP_URL).unlink(missing_ok=True)

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "github.com": {"A": ["127.0.0.88"]},
                "api.github.com": {"A": ["127.0.0.88"]},
                "bbc.co.uk": {"A": ["127.0.0.89"]},
                # affiliate: www.github.com is hosted on wikipedia's infrastructure
                "www.github.com": {"A": ["127.0.0.88"], "CNAME": ["edge.wikipedia.org"]},
                "edge.wikipedia.org": {"A": ["127.0.0.90"]},
            }
        )
        mock = module_test.blasthttp_mock
        self.bootstrap_calls = count_calls(
            mock, RDAP_BOOTSTRAP_URL, MockResponse(status_code=200, json=rdap_sample("iana_dns_bootstrap_trimmed"))
        )
        self.lookups = spy_lookups(module_test)
        self.registry_calls = {}
        samples = {
            "github.com": "verisign_com_github",
            "bbc.co.uk": "nominet_uk_bbc",
            "wikipedia.org": "pir_org_wikipedia",
        }
        for domain, url in self.registry_urls.items():
            self.registry_calls[domain] = count_calls(
                mock, url, MockResponse(status_code=200, json=rdap_sample(samples[domain]))
            )
        mock.add_response(
            url="https://rdap.markmonitor.com/rdap/domain/GITHUB.COM", json=rdap_sample("registrar_markmonitor_github")
        )
        # registrar has nothing on wikipedia.org: we still get the registry data
        mock.add_response(url="https://rdap.markmonitor.com/rdap/domain/wikipedia.org", status_code=404, text="")

    def check(self, module_test, events):
        registrations = [e for e in events if e.type == "DOMAIN_REGISTRATION"]
        hosts = sorted(e.data["host"] for e in registrations)
        # exactly one per registrable domain, even though github.com has several subdomains
        assert hosts == ["bbc.co.uk", "github.com", "wikipedia.org"], hosts
        for domain, calls in self.registry_calls.items():
            assert len(calls) == 1, f"{domain} was queried {len(calls)} times"
        # the bootstrap is downloaded once and reused
        assert len(self.bootstrap_calls) == 1, self.bootstrap_calls
        # names without a registrable domain never reach the lookup
        assert sorted(self.lookups) == ["bbc.co.uk", "github.com", "wikipedia.org"], self.lookups
        assert any(e.type == "DNS_NAME" and e.data == "host.local" for e in events)
        assert any(e.type == "DNS_NAME" and e.data == "co.uk" for e in events)

        github = next(e for e in registrations if e.data["host"] == "github.com")
        assert github.data["registrar"] == "MarkMonitor Inc."
        assert github.data["registrar_iana_id"] == "292"
        assert github.data["registrant_org"] == "GitHub, Inc."
        assert github.data["registrant_country"] == "US"
        assert github.data["registrant_redacted"] is True
        assert "registrant_name" not in github.data
        assert "registrant_email" not in github.data
        assert github.data["created"] == "2007-10-09T18:20:50Z"
        assert github.data["expires"] == "2028-10-09T18:20:50Z"
        assert github.data["rdap_updated"] == "2026-10-01T21:04:58Z"
        assert len(github.data["nameservers"]) == 8
        assert "dns1.p08.nsone.net" in github.data["nameservers"]
        assert github.data["status"] == [
            "client delete prohibited",
            "client transfer prohibited",
            "client update prohibited",
        ]
        assert github.data["rdap_server"] == self.registry_urls["github.com"]
        assert github.data["registrar_rdap_server"] == "https://rdap.markmonitor.com/rdap/domain/GITHUB.COM"
        assert "raw" not in github.data
        assert github.scope_distance == 0
        assert github.pretty_string == "github.com (MarkMonitor Inc.)"
        assert 'queried RDAP (https://rdap.verisign.com/com/v1/domain/github.com) for "github.com"' in (
            github.discovery_context
        )

        bbc = next(e for e in registrations if e.data["host"] == "bbc.co.uk")
        assert bbc.data["registrar"] == "British Broadcasting Corporation"
        assert "registrar_iana_id" not in bbc.data
        assert bbc.data["registrant_redacted"] is True
        assert bbc.data["nameservers"] == ["ddns0.bbc.co.uk", "ddns0.bbc.com"]
        assert bbc.scope_distance == 0

        # affiliate registrations reach output
        wikipedia = next(e for e in registrations if e.data["host"] == "wikipedia.org")
        assert wikipedia.data["registrar"] == "MarkMonitor Inc."
        assert wikipedia.data["expires"] == "2027-01-13T00:12:14Z"
        assert "registrar_rdap_server" not in wikipedia.data
        assert wikipedia.scope_distance > 0
        assert not wikipedia._internal


class TestRdapNoFollow(TestRdap):
    module_name = "rdap"
    targets = ["github.com"]
    config_overrides = {"modules": {"rdap": {"server_interval": 0, "follow_registrar": False, "include_raw": True}}}

    async def setup_after_prep(self, module_test):
        module_test.blasthttp_mock.add_response(url=RDAP_BOOTSTRAP_URL, json=rdap_sample("iana_dns_bootstrap_trimmed"))
        module_test.blasthttp_mock.add_response(
            url=self.registry_urls["github.com"], json=rdap_sample("verisign_com_github")
        )

    def check(self, module_test, events):
        registrations = [e for e in events if e.type == "DOMAIN_REGISTRATION"]
        assert len(registrations) == 1
        github = registrations[0]
        assert github.data["host"] == "github.com"
        assert github.data["registrar"] == "MarkMonitor Inc."
        assert "registrant_org" not in github.data
        assert github.data["registrant_redacted"] is False
        assert github.data["raw"]["registry"]["ldhName"] == "GITHUB.COM"
