from .base import ModuleTestBase


class TestShodan_Enterprise(ModuleTestBase):
    # the module expects an IP address target and a valid API key
    targets = ["8.8.8.8"]
    config_overrides = {"modules": {"shodan_enterprise": {"api_key": "deadbeef"}}}

    async def setup_before_prep(self, module_test):
        # the official shodan library uses `requests` under the hood, so
        # our httpx_mock is ineffective. import the library and patch the
        # Shodan.host method directly so we return predictable data.
        import shodan  # imported lazily to avoid breaking tests if missing

        fake_response = {
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
        }

        def fake_host(self, ips, history=False, minify=False):
            assert ips == "8.8.8.8"
            return fake_response

        module_test.monkeypatch.setattr(shodan.Shodan, "host", fake_host)

    def check(self, module_test, events):
        asn_events = [e for e in events if e.type == "ASN"]
        self.log.critical(f"Found {len(asn_events)} ASN events")
        assert asn_events, "No ASN event detected"
        asn = asn_events[0].data
        assert asn.get("asn") == "15169"
        assert asn.get("name") == "Google LLC"
        assert asn.get("country") == "US"
        assert asn.get("description") == "Google LLC"
        tcp_ports = [e.data for e in events if e.type == "OPEN_TCP_PORT"]
        udp_ports = [e.data for e in events if e.type == "OPEN_UDP_PORT"]
        self.log.critical(f"TCP ports: {tcp_ports}, UDP ports: {udp_ports}")
        assert any("8.8.8.8:53" in str(p) for p in tcp_ports), "TCP port 53 not detected"
        assert any("8.8.8.8:53" in str(p) for p in udp_ports), "UDP port 53 not detected"
        vuln_events = [e for e in events if e.type == "VULNERABILITY"]
        vuln_map = {e.data.get("description"): e.data.get("severity") for e in vuln_events}
        self.log.hugewarning(f"Vulnerabilities observed: {vuln_map}")
        assert "CVE-2021-12345" in vuln_map
        assert vuln_map["CVE-2021-12345"] == "HIGH"
        assert "CVE-2020-00001" in vuln_map
        assert vuln_map["CVE-2020-00001"] == "LOW"
        tech_events = [e for e in events if e.type == "TECHNOLOGY"]
        tech_names = {e.data.get("technology") for e in tech_events}
        assert "cpe:/a:google:dns" in tech_names
        assert "Google Public DNS" in tech_names
        assert "OpenSSL" in tech_names
        assert "nginx" in tech_names
