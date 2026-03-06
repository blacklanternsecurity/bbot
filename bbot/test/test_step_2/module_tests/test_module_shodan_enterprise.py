from .base import ModuleTestBase


class TestShodan_Enterprise(ModuleTestBase):
    targets = ["8.8.8.8"]
    config_overrides = {"modules": {"shodan_enterprise": {"api_key": "deadbeef"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.shodan.io/shodan/host/8.8.8.8?key=deadbeef",
            json={
                "asn": "AS15169",
                "org": "Google LLC",
                "isp": "Google LLC",
                "country_code": "US",
                "tags": ["cloud", "public-dns", "verified"],
                "data": [
                    {
                        "ip_str": "8.8.8.8",
                        "port": 53,
                        "transport": "tcp",
                        "product": "Google Public DNS",
                        "tags": ["dns", "nameserver"],
                        "cpe": ["cpe:/a:google:dns"],
                        "cpe23": ["cpe:2.3:a:google:dns:1.0:*:*:*:*:*:*:*"],
                        "http": {
                            "components": {
                                "OpenSSL": {"categories": ["web-crypto"]},
                                "nginx": {"categories": ["web-servers"]},
                            }
                        },
                        "vulns": {
                            "CVE-2021-12345": {"cvss": 7.5},
                            "CVE-2022-11111": {"cvss": 9.7},
                            "CVE-2020-00001": {"cvss": 2.5},
                        },
                    },
                    {
                        "ip_str": "8.8.8.8",
                        "port": 53,
                        "transport": "udp",
                        "product": "Google Public DNS",
                        "tags": ["dns"],
                        "cpe": [],
                        "cpe23": [],
                        "http": {},
                        "vulns": {},
                    },
                ],
            },
        )

    def check(self, module_test, events):
        asn_events = [e for e in events if e.type == "ASN"]
        assert asn_events, "No ASN event detected"
        asn = asn_events[0].data
        assert asn.get("asn") == "15169"
        assert asn.get("name") == "Google LLC"
        assert asn.get("country") == "US"
        assert asn.get("description") == "Google LLC"
        tcp_ports = [e.data for e in events if e.type == "OPEN_TCP_PORT"]
        udp_ports = [e.data for e in events if e.type == "OPEN_UDP_PORT"]
        assert any("8.8.8.8:53" in str(p) for p in tcp_ports), "TCP port 53 not detected"
        assert any("8.8.8.8:53" in str(p) for p in udp_ports), "UDP port 53 not detected"
        finding_events = [e for e in events if e.type == "FINDING"]
        finding_map = {e.data.get("description"): e.data.get("severity") for e in finding_events}
        assert "CVE-2021-12345" in finding_map
        assert finding_map["CVE-2021-12345"] == "HIGH"
        assert "CVE-2020-00001" in finding_map
        assert finding_map["CVE-2020-00001"] == "LOW"
        tech_events = [e for e in events if e.type == "TECHNOLOGY"]
        tech_names = {e.data.get("technology") for e in tech_events}
        assert "cpe:/a:google:dns" in tech_names
        assert "google public dns" in tech_names
        assert "openssl" in tech_names
        assert "nginx" in tech_names
