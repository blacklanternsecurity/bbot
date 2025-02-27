from .base import ModuleTestBase


class TestShodan_IDB(ModuleTestBase):
    config_overrides = {"dns": {"minimal": False}}

    async def setup_before_prep(self, module_test):
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
                "vulns": ["CVE-2021-26857", "CVE-2021-26855"],
            },
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
        assert 1 == len([e for e in events if e.type == "FINDING" and str(e.module) == "shodan_idb"])
        assert 1 == len([e for e in events if e.type == "FINDING" and "CVE-2021-26857" in e.data["description"]])
        assert 2 == len([e for e in events if e.type == "TECHNOLOGY" and str(e.module) == "shodan_idb"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "TECHNOLOGY" and e.data["technology"] == "cpe:/a:microsoft:outlook_web_access:15.0.1367"
            ]
        )
