from .base import ModuleTestBase


class TestCensys_IP(ModuleTestBase):
    targets = ["1.2.3.4"]
    config_overrides = {"modules": {"censys_ip": {"api_key": "api_id:api_secret"}}}

    async def setup_before_prep(self, module_test):
        await module_test.mock_dns(
            {
                "wildcard.evilcorp.com": {
                    "A": ["1.2.3.4"],
                },
                "certname.evilcorp.com": {
                    "A": ["1.2.3.4"],
                },
                "certsubject.evilcorp.com": {
                    "A": ["1.2.3.4"],
                },
                "reversedns.evilcorp.com": {
                    "A": ["1.2.3.4"],
                },
                "ptr.evilcorp.com": {
                    "A": ["1.2.3.4"],
                },
            }
        )
        module_test.httpx_mock.add_response(
            url="https://search.censys.io/api/v1/account",
            match_headers={"Authorization": "Basic YXBpX2lkOmFwaV9zZWNyZXQ="},
            json={
                "email": "info@blacklanternsecurity.com",
                "login": "nope",
                "first_login": "1917-08-03 20:03:55",
                "last_login": "1918-05-19 01:15:22",
                "quota": {"used": 26, "allowance": 250, "resets_at": "1919-06-03 16:30:32"},
            },
        )
        module_test.httpx_mock.add_response(
            url="https://search.censys.io/api/v2/hosts/1.2.3.4",
            match_headers={"Authorization": "Basic YXBpX2lkOmFwaV9zZWNyZXQ="},
            json={
                "code": 200,
                "status": "OK",
                "result": {
                    "ip": "1.2.3.4",
                    "services": [
                        {
                            "port": 53,
                            "service_name": "DNS",
                            "transport_protocol": "UDP",
                        },
                        {
                            "port": 80,
                            "service_name": "HTTP",
                            "extended_service_name": "HTTP",
                            "transport_protocol": "TCP",
                            "http": {
                                "request": {
                                    "method": "GET",
                                    "uri": "http://1.2.3.4/",
                                },
                            },
                        },
                        {
                            "port": 443,
                            # Real API returns service_name: "HTTP" for HTTPS
                            "service_name": "HTTP",
                            "extended_service_name": "HTTPS",
                            "transport_protocol": "TCP",
                            "http": {
                                "request": {
                                    "method": "GET",
                                    "uri": "https://1.2.3.4/",
                                },
                            },
                            "tls": {
                                "certificates": {
                                    "leaf_data": {
                                        "names": [
                                            "*.wildcard.evilcorp.com",
                                            "certname.evilcorp.com",
                                        ],
                                        "subject": {
                                            "common_name": ["certsubject.evilcorp.com"],
                                        },
                                    },
                                },
                            },
                        },
                        {
                            "port": 8443,
                            # Real API returns service_name: "HTTP" for HTTPS
                            "service_name": "HTTP",
                            "extended_service_name": "HTTPS",
                            "transport_protocol": "TCP",
                            "http": {
                                "request": {
                                    "method": "GET",
                                    "uri": "https://1.2.3.4:8443/admin",
                                },
                            },
                            "software": [
                                {
                                    "uniform_resource_identifier": "cpe:2.3:a:apache:tomcat:9.0.50:*:*:*:*:*:*:*",
                                    "product": "Apache Tomcat",
                                    "vendor": "Apache",
                                },
                                {
                                    "product": "Java",
                                },
                            ],
                        },
                        {
                            "port": 22,
                            "service_name": "SSH",
                            "extended_service_name": "SSH",
                            "transport_protocol": "TCP",
                        },
                        {
                            "port": 443,
                            # Real API returns service_name: "UNKNOWN" and transport_protocol: "QUIC"
                            "service_name": "UNKNOWN",
                            "extended_service_name": "UNKNOWN",
                            "transport_protocol": "QUIC",
                        },
                    ],
                    "dns": {
                        "names": [
                            "reversedns.evilcorp.com",
                            "ptr.evilcorp.com",
                        ],
                    },
                },
            },
        )

    def check(self, module_test, events):
        # Check OPEN_UDP_PORT event for DNS
        assert any(e.type == "OPEN_UDP_PORT" and e.data == "1.2.3.4:53" for e in events), (
            "Failed to detect UDP port 53"
        )

        # Check OPEN_TCP_PORT events
        assert any(e.type == "OPEN_TCP_PORT" and e.data == "1.2.3.4:22" for e in events), (
            "Failed to detect TCP port 22 (SSH)"
        )
        assert any(e.type == "OPEN_TCP_PORT" and e.data == "1.2.3.4:80" for e in events), (
            "Failed to detect TCP port 80"
        )
        assert any(e.type == "OPEN_TCP_PORT" and e.data == "1.2.3.4:443" for e in events), (
            "Failed to detect TCP port 443"
        )
        assert any(e.type == "OPEN_TCP_PORT" and e.data == "1.2.3.4:8443" for e in events), (
            "Failed to detect TCP port 8443"
        )

        # Check OPEN_UDP_PORT for QUIC
        assert any(e.type == "OPEN_UDP_PORT" and e.data == "1.2.3.4:443" for e in events), (
            "Failed to detect UDP port 443 (QUIC)"
        )

        # Check URL_UNVERIFIED events
        assert any(e.type == "URL_UNVERIFIED" and e.data == "http://1.2.3.4/" for e in events), (
            "Failed to detect HTTP URL"
        )
        assert any(e.type == "URL_UNVERIFIED" and e.data == "https://1.2.3.4/" for e in events), (
            "Failed to detect HTTPS URL"
        )
        assert any(e.type == "URL_UNVERIFIED" and e.data == "https://1.2.3.4:8443/admin" for e in events), (
            "Failed to detect HTTPS URL on port 8443"
        )

        # Check DNS_NAME events from TLS certificate names
        assert any(e.type == "DNS_NAME" and e.data == "wildcard.evilcorp.com" for e in events), (
            "Failed to detect wildcard.evilcorp.com from TLS cert names (wildcard stripped)"
        )
        assert any(e.type == "DNS_NAME" and e.data == "certname.evilcorp.com" for e in events), (
            "Failed to detect certname.evilcorp.com from TLS cert names"
        )

        # Check DNS_NAME events from TLS certificate subject common_name
        assert any(
            e.type == "DNS_NAME" and e.data == "certsubject.evilcorp.com" and e.scope_distance == 0 for e in events
        ), "Failed to detect certsubject.evilcorp.com from TLS cert subject"

        # Check DNS_NAME events from dns.names (reverse DNS)
        assert any(e.type == "DNS_NAME" and e.data == "reversedns.evilcorp.com" for e in events), (
            "Failed to detect reversedns.evilcorp.com from reverse DNS"
        )
        assert any(e.type == "DNS_NAME" and e.data == "ptr.evilcorp.com" for e in events), (
            "Failed to detect ptr.evilcorp.com from reverse DNS"
        )

        # Check TECHNOLOGY events from software
        assert any(
            e.type == "TECHNOLOGY" and e.data["technology"] == "cpe:2.3:a:apache:tomcat:9.0.50:*:*:*:*:*:*:*"
            for e in events
        ), "Failed to detect Apache Tomcat technology with CPE"
        assert any(e.type == "TECHNOLOGY" and e.data["technology"] == "Java" for e in events), (
            "Failed to detect Java technology without CPE"
        )

        # Check PROTOCOL events (non-HTTP/DNS services)
        assert any(
            e.type == "PROTOCOL" and e.data["protocol"] == "SSH" and e.data.get("port") == 22 for e in events
        ), "Failed to detect SSH protocol"
        assert any(
            e.type == "PROTOCOL" and e.data["protocol"] == "QUIC" and e.data.get("port") == 443 for e in events
        ), "Failed to detect QUIC protocol"

        # Ensure HTTP/HTTPS services don't emit PROTOCOL events (but DNS does)
        assert not any(e.type == "PROTOCOL" and e.data["protocol"] in ("HTTP", "HTTPS") for e in events), (
            "Should not emit PROTOCOL for HTTP/HTTPS services"
        )
        assert any(e.type == "PROTOCOL" and e.data["protocol"] == "DNS" for e in events), (
            "Should emit PROTOCOL for DNS services"
        )


class TestCensys_IP_InScopeOnly(ModuleTestBase):
    """Test that in_scope_only=True (default) does NOT query out-of-scope IPs."""

    targets = ["evilcorp.com"]
    module_name = "censys_ip"
    config_overrides = {"modules": {"censys_ip": {"api_key": "api_id:api_secret", "in_scope_only": True}}}

    async def setup_before_prep(self, module_test):
        await module_test.mock_dns({"evilcorp.com": {"A": ["1.1.1.1"]}})
        module_test.httpx_mock.add_response(
            url="https://search.censys.io/api/v1/account",
            match_headers={"Authorization": "Basic YXBpX2lkOmFwaV9zZWNyZXQ="},
            json={
                "quota": {"used": 26, "allowance": 250, "resets_at": "1919-06-03 16:30:32"},
            },
        )
        # This should NOT be called because in_scope_only=True
        module_test.httpx_mock.add_response(
            url="https://search.censys.io/api/v2/hosts/1.1.1.1",
            match_headers={"Authorization": "Basic YXBpX2lkOmFwaV9zZWNyZXQ="},
            json={
                "code": 200,
                "status": "OK",
                "result": {
                    "ip": "1.1.1.1",
                    "services": [{"port": 80, "service_name": "HTTP", "transport_protocol": "TCP"}],
                },
            },
        )

    def check(self, module_test, events):
        # Should NOT have queried the IP since it's out of scope
        assert not any(e.type == "OPEN_TCP_PORT" and "1.1.1.1" in e.data for e in events), (
            "Should not have queried out-of-scope IP with in_scope_only=True"
        )


class TestCensys_IP_OutOfScope(ModuleTestBase):
    """Test that in_scope_only=False DOES query out-of-scope IPs (up to distance 1)."""

    targets = ["evilcorp.com"]
    module_name = "censys_ip"
    config_overrides = {
        "modules": {"censys_ip": {"api_key": "api_id:api_secret", "in_scope_only": False}},
        "dns": {"minimal": False},
        "scope": {"report_distance": 1},
    }

    async def setup_before_prep(self, module_test):
        await module_test.mock_dns({"evilcorp.com": {"A": ["1.1.1.1"]}})
        module_test.httpx_mock.add_response(
            url="https://search.censys.io/api/v1/account",
            match_headers={"Authorization": "Basic YXBpX2lkOmFwaV9zZWNyZXQ="},
            json={
                "quota": {"used": 26, "allowance": 250, "resets_at": "1919-06-03 16:30:32"},
            },
        )
        # This SHOULD be called because in_scope_only=False
        module_test.httpx_mock.add_response(
            url="https://search.censys.io/api/v2/hosts/1.1.1.1",
            match_headers={"Authorization": "Basic YXBpX2lkOmFwaV9zZWNyZXQ="},
            json={
                "code": 200,
                "status": "OK",
                "result": {
                    "ip": "1.1.1.1",
                    "services": [{"port": 80, "service_name": "HTTP", "transport_protocol": "TCP"}],
                },
            },
        )

    def check(self, module_test, events):
        # Should have queried the IP since in_scope_only=False
        assert any(e.type == "OPEN_TCP_PORT" and e.data == "1.1.1.1:80" for e in events), (
            "Should have queried out-of-scope IP with in_scope_only=False"
        )
