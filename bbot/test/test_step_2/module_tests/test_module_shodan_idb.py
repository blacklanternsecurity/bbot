from .base import ModuleTestBase


class TestShodan_IDB(ModuleTestBase):
    config_overrides = {"dns": {"minimal": False}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "autodiscover.blacklanternsecurity.com": {"A": ["2.3.4.5"]},
                "mail.blacklanternsecurity.com": {"A": ["3.4.5.6"]},
            }
        )

        module_test.httpx_mock.add_response(
            url="https://internetdb.shodan.io/1.2.3.4",
            json={
                "cpes": [
                    "cpe:/a:microsoft:internet_information_services",
                    "cpe:/a:microsoft:outlook_web_access:15.0.1367",
                ],
                "hostnames": [
                    "autodiscover.blacklanternsecurity.com",
                    "mail.blacklanternsecurity.com",
                ],
                "ip": "1.2.3.4",
                "ports": [
                    25,
                    80,
                    443,
                ],
                "tags": ["starttls", "self-signed", "eol-os"],
                # CVE-2021-26857 is intentionally listed twice to exercise the per-scan
                # CVE detail cache: the second occurrence must hit the cache rather than
                # making a second CVEDB request (the mock below is single-use).
                "vulns": ["CVE-2021-26857", "CVE-2021-26855", "CVE-2021-26857"],
            },
        )

        # CVEDB enrichment lookups (each mock is single-use by default in pytest-httpx,
        # so a cache miss on a repeat lookup would fail to find a mock and raise).
        module_test.httpx_mock.add_response(
            url="https://cvedb.shodan.io/cve/CVE-2021-26857",
            json={"cve_id": "CVE-2021-26857", "cvss_v3": 7.8},
        )
        module_test.httpx_mock.add_response(
            url="https://cvedb.shodan.io/cve/CVE-2021-26855",
            json={"cve_id": "CVE-2021-26855", "cvss_v3": 9.1},
        )

    def check(self, module_test, events):
        assert 8 == len([e for e in events if str(e.module) == "shodan_idb"])
        assert 1 == len(
            [e for e in events if e.type == "DNS_NAME" and e.data == "autodiscover.blacklanternsecurity.com"]
        )
        assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "mail.blacklanternsecurity.com"])
        assert 3 == len(
            [
                e
                for e in events
                if e.type == "OPEN_TCP_PORT" and e.host == "blacklanternsecurity.com" and str(e.module) == "shodan_idb"
            ]
        )
        finding_events = [e for e in events if e.type == "FINDING" and str(e.module) == "shodan_idb"]
        assert 1 == len(finding_events)
        finding = finding_events[0]
        description = finding.data["description"]
        # host appears in the description
        assert "blacklanternsecurity.com" in description
        # per-CVE entries with severity and CVSS
        assert "CVE-2021-26857 [HIGH, 7.8]" in description
        assert "CVE-2021-26855 [CRITICAL, 9.1]" in description
        # highest-CVSS CVE comes first in the inline list
        assert description.index("CVE-2021-26855") < description.index("CVE-2021-26857")
        # description is single-line
        assert "\n" not in description
        # overall severity is hard-coded to INFO (banner match, not confirmed exploit)
        assert finding.data["severity"] == "INFO"
        assert 2 == len([e for e in events if e.type == "TECHNOLOGY" and str(e.module) == "shodan_idb"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "TECHNOLOGY" and e.data["technology"] == "cpe:/a:microsoft:outlook_web_access:15.0.1367"
            ]
        )

        # CVE detail cache should be populated for each unique CVE
        cve_cache = module_test.module._cve_cache
        assert set(cve_cache.keys()) == {"CVE-2021-26857", "CVE-2021-26855"}
        assert cve_cache["CVE-2021-26857"]["cvss_v3"] == 7.8
        assert cve_cache["CVE-2021-26855"]["cvss_v3"] == 9.1

        # CVEDB should be hit exactly once per unique CVE; the duplicate CVE-2021-26857
        # in vulns must hit the cache rather than triggering a second request.
        cvedb_requests = [
            r for r in module_test.httpx_mock.get_requests() if r.url.host and r.url.host == "cvedb.shodan.io"
        ]
        assert len(cvedb_requests) == 2, f"expected 2 CVEDB requests, got {len(cvedb_requests)}"
        assert sorted(str(r.url) for r in cvedb_requests) == [
            "https://cvedb.shodan.io/cve/CVE-2021-26855",
            "https://cvedb.shodan.io/cve/CVE-2021-26857",
        ]
