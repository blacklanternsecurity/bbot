import inspect
import time
from urllib.parse import parse_qs, urlparse

import pytest

from bbot.test.mock_blasthttp import MockResponse

from .base import ModuleTestBase


def count_response(*ips):
    """A /shodan/host/count body with an ip facet. The module only reads facets.ip[*].value."""
    return {"total": len(ips), "matches": [], "facets": {"ip": [{"value": ip, "count": 1} for ip in ips]}}


def mock_count(module_test, payload, record=None):
    """Answer /shodan/host/count through BBOT's own HTTP mock."""

    async def _cb(request):
        url = str(request.url)
        if record is not None:
            record.append(url)
        return MockResponse(status_code=200, json=payload)

    module_test.blasthttp_mock.add_callback(_cb, url=None)


host_response_8_8_8_8 = {
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


class TestShodan_Enterprise(ModuleTestBase):
    """A single IP is looked up directly: a count query would only add a request."""

    targets = ["8.8.8.8"]
    config_overrides = {"modules": {"shodan_enterprise": {"api_key": "deadbeef"}}}

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://api.shodan.io/shodan/host/8.8.8.8?key=deadbeef",
            json=host_response_8_8_8_8,
        )

    async def setup_after_prep(self, module_test):
        self.count_calls = []
        mock_count(module_test, count_response("8.8.8.8"), record=self.count_calls)

    def check(self, module_test, events):
        assert self.count_calls == [], f"a single IP should skip the count query: {self.count_calls}"

        tcp_ports = [e.data for e in events if e.type == "OPEN_TCP_PORT"]
        udp_ports = [e.data for e in events if e.type == "OPEN_UDP_PORT"]
        assert any("8.8.8.8:53" in str(p) for p in tcp_ports), "TCP port 53 not detected"
        # the count index withholds this UDP banner, so only the direct lookup finds it
        assert any("8.8.8.8:53" in str(p) for p in udp_ports), "UDP port 53 not detected"

        finding_events = [e for e in events if e.type == "FINDING"]
        finding_map = {e.data["cves"][0]: e.data.get("severity") for e in finding_events}
        assert "CVE-2021-12345" in finding_map
        assert finding_map["CVE-2021-12345"] == "HIGH"
        assert "CVE-2020-00001" in finding_map
        assert finding_map["CVE-2020-00001"] == "LOW"

        # the finding descends from the port event of its banner
        by_cve = {e.data["cves"][0]: e for e in finding_events}
        finding = by_cve["CVE-2021-12345"]
        assert finding.parent.type == "OPEN_TCP_PORT", (
            f"FINDING should hang off the port it was found on, got {finding.parent.type}"
        )
        assert "8.8.8.8:53" in str(finding.parent.data)
        assert finding.data.get("cves") == ["CVE-2021-12345"]
        # the service and score are named in the finding itself
        assert finding.data["description"] == "CVE-2021-12345 on 53/tcp (CVSS 7.5)", (
            f"finding should name the affected service, got {finding.data['description']!r}"
        )
        # host and port are inherited from the banner's port event (#3462)
        assert str(finding.host) == "8.8.8.8"
        assert finding.port == 53, f"finding should carry its banner's port, got {finding.port}"

        tech_events = [e for e in events if e.type == "TECHNOLOGY"]
        tech_names = {e.data.get("technology") for e in tech_events}
        # named by CPE product, with the CPE retained
        assert "dns" in tech_names
        assert any(e.data.get("cpe") == "cpe:2.3:a:google:dns:1.0:*:*:*:*:*:*:*" for e in tech_events)
        # the udp banner has no CPE, so it falls back to Shodan's product name
        assert "google public dns" in tech_names
        assert not any(name.startswith("cpe:") for name in tech_names)
        assert "openssl" in tech_names
        assert "nginx" in tech_names

        # each technology hangs off the port of the first banner that reports it
        parents = {e.data["technology"]: e.parent.type for e in tech_events}
        assert parents["dns"] == "OPEN_TCP_PORT", parents
        assert parents["openssl"] == parents["nginx"] == "OPEN_TCP_PORT", parents
        assert parents["google public dns"] == "OPEN_UDP_PORT", parents
        assert all("port" not in e.data for e in tech_events), (
            "TECHNOLOGY data should not carry a port key that the validator drops"
        )


def host_response_vuln_on_ports(ip, *ports, cve="CVE-2021-12345", cvss=7.5):
    """A host running the same vulnerable product on several TCP ports."""
    return {
        "data": [
            {
                "ip_str": ip,
                "port": port,
                "transport": "tcp",
                "tags": [],
                "cpe": [],
                "cpe23": [],
                "http": {},
                "vulns": {cve: {"cvss": cvss}},
            }
            for port in ports
        ]
    }


class TestShodan_Enterprise_FindingPerPort(ModuleTestBase):
    """The same CVE on two services is two findings, not one."""

    targets = ["8.8.8.8"]
    module_name = "shodan_enterprise"
    config_overrides = {"modules": {"shodan_enterprise": {"api_key": "deadbeef"}}}

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://api.shodan.io/shodan/host/8.8.8.8?key=deadbeef",
            json=host_response_vuln_on_ports("8.8.8.8", 80, 443),
        )

    async def setup_after_prep(self, module_test):
        mock_count(module_test, count_response("8.8.8.8"))

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        descriptions = sorted(e.data["description"] for e in findings)
        assert descriptions == ["CVE-2021-12345 on 443/tcp (CVSS 7.5)", "CVE-2021-12345 on 80/tcp (CVSS 7.5)"], (
            f"expected one finding per affected service, got {descriptions}"
        )
        parents = sorted(str(e.parent.data) for e in findings)
        assert parents == ["8.8.8.8:443", "8.8.8.8:80"], parents
        # event.port matches the port named in the description
        for e in findings:
            described = int(e.data["description"].split(" on ")[1].split("/")[0])
            assert e.port == described, f"{e.data['description']!r} carries port {e.port}"


class TestShodan_Enterprise_FindingWithoutPort(ModuleTestBase):
    """A banner with no usable port still yields a finding, without a service suffix."""

    targets = ["8.8.8.8"]
    module_name = "shodan_enterprise"
    config_overrides = {"modules": {"shodan_enterprise": {"api_key": "deadbeef"}}}

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://api.shodan.io/shodan/host/8.8.8.8?key=deadbeef",
            json={"data": [{"ip_str": "8.8.8.8", "vulns": {"CVE-2021-12345": {"cvss": 7.5}}}]},
        )

    async def setup_after_prep(self, module_test):
        mock_count(module_test, count_response("8.8.8.8"))

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert len(findings) == 1, f"expected the finding to survive a portless banner, got {len(findings)}"
        assert findings[0].data["description"] == "CVE-2021-12345 (CVSS 7.5)", findings[0].data["description"]
        assert findings[0].data["cves"] == ["CVE-2021-12345"]


class TestShodan_Enterprise_CyclesApiKeyOnRateLimit(ModuleTestBase):
    """A 429 must move the retry to the next API key."""

    targets = ["8.8.8.8"]
    module_name = "shodan_enterprise"
    config_overrides = {
        "modules": {
            "shodan_enterprise": {
                "api_key": ["key1", "key2"],
                "requests_per_second": 1000,
            }
        },
        "web": {"429_sleep_interval": 1, "429_max_sleep_interval": 1},
    }

    async def setup_after_prep(self, module_test):
        self.lookup_urls = []

        async def _cb(request):
            url = str(request.url)
            if "/shodan/host/count" in url:
                return MockResponse(status_code=200, json=count_response("8.8.8.8"))
            self.lookup_urls.append(url)
            if len(self.lookup_urls) == 1:
                return MockResponse(status_code=429, json={"error": "rate limited"})
            return MockResponse(status_code=200, json=host_response_8_8_8_8)

        module_test.blasthttp_mock.add_callback(_cb, url=None)

    def check(self, module_test, events):
        assert len(self.lookup_urls) >= 2, f"expected a retry after the 429, got {self.lookup_urls}"
        assert "key=key1" in self.lookup_urls[0], self.lookup_urls[0]
        assert "key=key2" in self.lookup_urls[1], f"retry after 429 reused the rate-limited key: {self.lookup_urls[1]}"
        assert any(e.type == "OPEN_TCP_PORT" for e in events), "the retry should have succeeded"


class TestShodan_Enterprise_ApiRequestsAvoidBrowserUserAgent(ModuleTestBase):
    """API calls must not inherit the browser User-Agent from the scan config (Cloudflare challenges it)."""

    targets = ["8.8.8.8"]
    module_name = "shodan_enterprise"
    _browser_ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.2151.97"
    )
    config_overrides = {
        "modules": {"shodan_enterprise": {"api_key": "deadbeef"}},
        "web": {"user_agent": _browser_ua},
    }

    async def setup_after_prep(self, module_test):
        self.seen_agents = []

        async def _cb(request):
            headers = {k.lower(): v for k, v in dict(request.headers).items()}
            self.seen_agents.append(headers.get("user-agent"))
            return MockResponse(status_code=200, json=host_response_8_8_8_8)

        module_test.blasthttp_mock.add_callback(_cb, url=None)

    def check(self, module_test, events):
        assert self.seen_agents, "the lookup never reached BBOT's HTTP layer"
        for ua in self.seen_agents:
            assert ua, "API request left User-Agent to the scan config"
            assert "Mozilla" not in ua, f"API request carried a browser-like User-Agent: {ua!r}"
        assert any(e.type == "OPEN_TCP_PORT" for e in events)


shodan_response_1_1_1_1 = {
    "data": [
        {
            "ip_str": "1.1.1.1",
            "port": 80,
            "transport": "tcp",
            "product": "cloudflare",
            "tags": [],
            "cpe": [],
            "cpe23": [],
            "http": {},
            "vulns": {},
        },
    ],
}


class TestShodan_Enterprise_InScopeOnly(ModuleTestBase):
    """Test that in_scope_only=True (default) does NOT query out-of-scope IPs."""

    targets = ["evilcorp.notreal"]
    module_name = "shodan_enterprise"
    config_overrides = {"modules": {"shodan_enterprise": {"api_key": "deadbeef"}}}

    async def setup_before_prep(self, module_test):
        # This should NOT be called because in_scope_only=True
        module_test.blasthttp_mock.add_response(
            url="https://api.shodan.io/shodan/host/1.1.1.1?key=deadbeef",
            json=shodan_response_1_1_1_1,
        )

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({"evilcorp.notreal": {"A": ["1.1.1.1"]}})
        mock_count(module_test, count_response("1.1.1.1"))

    def check(self, module_test, events):
        assert not any(e.type == "OPEN_TCP_PORT" and "1.1.1.1" in e.data for e in events), (
            "Should not have queried out-of-scope IP with in_scope_only=True"
        )


class TestShodan_Enterprise_OutOfScope(ModuleTestBase):
    """Test that in_scope_only=False DOES query out-of-scope IPs (up to distance 1)."""

    targets = ["evilcorp.notreal"]
    module_name = "shodan_enterprise"
    config_overrides = {
        "modules": {"shodan_enterprise": {"api_key": "deadbeef", "in_scope_only": False}},
        "dns": {"minimal": False},
        "scope": {"report_distance": 1},
    }

    async def setup_before_prep(self, module_test):
        # This SHOULD be called because in_scope_only=False
        module_test.blasthttp_mock.add_response(
            url="https://api.shodan.io/shodan/host/1.1.1.1?key=deadbeef",
            json=shodan_response_1_1_1_1,
        )

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({"evilcorp.notreal": {"A": ["1.1.1.1"]}})
        mock_count(module_test, count_response("1.1.1.1"))

    def check(self, module_test, events):
        assert any(e.type == "OPEN_TCP_PORT" and e.data == "1.1.1.1:80" for e in events), (
            "Should have queried out-of-scope IP with in_scope_only=False"
        )


def host_record(ip, port=443):
    return {"data": [{"ip_str": ip, "port": port, "transport": "tcp", "vulns": {}}]}


class TestShodan_Enterprise_TransientRateLimitDoesNotError(ModuleTestBase):
    """A few 429s from a single key are normal operation, not a failure."""

    targets = ["8.8.8.8"]
    module_name = "shodan_enterprise"
    config_overrides = {
        "modules": {
            "shodan_enterprise": {"api_key": "deadbeef", "requests_per_second": 1000, "search_prefilter": False}
        },
        "web": {"429_sleep_interval": 1, "429_max_sleep_interval": 1},
    }

    async def setup_after_prep(self, module_test):
        self.lookups = 0

        async def _cb(request):
            self.lookups += 1
            if self.lookups <= 2:
                return MockResponse(status_code=429, json={"error": "rate limited"}, headers={"Retry-After": "1"})
            return MockResponse(status_code=200, json=host_record("8.8.8.8"))

        module_test.blasthttp_mock.add_callback(_cb, url=None)

    def check(self, module_test, events):
        assert self.lookups == 3, f"expected two 429s and one success, got {self.lookups} requests"
        assert any(e.type == "OPEN_TCP_PORT" and e.data == "8.8.8.8:443" for e in events)
        assert module_test.module.errored is False, "two 429s must not take the module down"


class TestShodan_Enterprise_PersistentRateLimitErrors(ModuleTestBase):
    """A key that is rate limited on every request errors the module out so the scan can finish."""

    _ips = [f"198.51.100.{i}" for i in range(1, 26)]
    targets = _ips
    module_name = "shodan_enterprise"
    config_overrides = {
        "modules": {
            "shodan_enterprise": {"api_key": "deadbeef", "requests_per_second": 1000, "search_prefilter": False}
        },
        "web": {"api_retries": 0, "429_sleep_interval": 1, "429_max_sleep_interval": 1},
        "dns": {"minimal": True},
    }

    async def setup_after_prep(self, module_test):
        self.lookups = 0

        async def _cb(request):
            self.lookups += 1
            return MockResponse(status_code=429, json={"error": "rate limited"}, headers={"Retry-After": "1"})

        module_test.blasthttp_mock.add_callback(_cb, url=None)

    def check(self, module_test, events):
        module = module_test.module
        assert module.errored is True, "the module kept going on a key that is always rate limited"
        ceiling = module.api_rate_limit_abort_threshold + module.concurrency
        assert self.lookups <= ceiling, f"{self.lookups} requests after the module should have stopped at ~{ceiling}"
        assert not any(e.type == "OPEN_TCP_PORT" for e in events)


class TestShodan_Enterprise_HostNotFound(ModuleTestBase):
    """A 404 from the host endpoint means "no data", not a failure."""

    _ips = ["198.51.100.1", "198.51.100.2"]
    targets = _ips
    module_name = "shodan_enterprise"
    config_overrides = {
        "modules": {
            "shodan_enterprise": {"api_key": "deadbeef", "requests_per_second": 1000, "search_prefilter": False}
        },
        "dns": {"minimal": True},
    }

    async def setup_after_prep(self, module_test):
        async def _cb(request):
            url = str(request.url)
            if "/shodan/host/198.51.100.1?" in url:
                return MockResponse(status_code=404, json={"error": "No information available for that IP."})
            return MockResponse(status_code=200, json=host_record("198.51.100.2"))

        module_test.blasthttp_mock.add_callback(_cb, url=None)

    def check(self, module_test, events):
        ports = {e.data for e in events if e.type == "OPEN_TCP_PORT"}
        assert ports == {"198.51.100.2:443"}, ports
        assert module_test.module.errored is False
        warnings = [
            r.getMessage()
            for r in module_test.caplog.records
            if r.levelname == "WARNING" and "198.51.100.1" in r.getMessage()
        ]
        assert not warnings, f"a 404 was reported as a problem: {warnings}"


class TestShodan_Enterprise_ThrottleSpacesRequests(ModuleTestBase):
    """requests_per_second paces requests before they are sent, across concurrent lookups."""

    _ips = [f"198.51.100.{i}" for i in range(1, 7)]
    targets = _ips
    module_name = "shodan_enterprise"
    config_overrides = {
        "modules": {
            "shodan_enterprise": {
                "api_key": "deadbeef",
                "requests_per_second": 5,
                "concurrency": 4,
                "search_prefilter": False,
            }
        },
        "dns": {"minimal": True},
    }

    async def setup_after_prep(self, module_test):
        self.sent_at = []

        async def _cb(request):
            url = str(request.url)
            self.sent_at.append(time.monotonic())
            ip = url.split("/shodan/host/")[-1].split("?")[0]
            return MockResponse(status_code=200, json=host_record(ip))

        module_test.blasthttp_mock.add_callback(_cb, url=None)

    def check(self, module_test, events):
        assert len(self.sent_at) == len(self._ips), self.sent_at
        span = max(self.sent_at) - min(self.sent_at)
        expected = (len(self._ips) - 1) / 5
        assert span >= expected * 0.8, f"{len(self._ips)} requests in {span:.2f}s, expected at least {expected:.2f}s"
        assert "import asyncio" not in inspect.getsource(inspect.getmodule(type(module_test.module))), (
            "modules don't import asyncio"
        )


class TestShodan_Enterprise_StopsWorkingOnceErrored(ModuleTestBase):
    """Once api_request() has errored the module out, nothing waits on the throttle."""

    _ips = [f"198.51.100.{i}" for i in range(1, 31)]
    targets = _ips
    module_name = "shodan_enterprise"
    config_overrides = {
        "modules": {
            "shodan_enterprise": {
                "api_key": "deadbeef",
                "requests_per_second": 1000,
                "search_prefilter": False,
                "concurrency": 1,
            }
        },
        "web": {"api_retries": 0, "429_sleep_interval": 1, "429_max_sleep_interval": 1},
        "dns": {"minimal": True},
    }

    async def setup_after_prep(self, module_test):
        async def _cb(request):
            return MockResponse(status_code=429, json={"error": "rate limited"}, headers={"Retry-After": "1"})

        module_test.blasthttp_mock.add_callback(_cb, url=None)

        module = module_test.module
        self.throttled_after_error = 0
        real_throttle = module._throttle

        async def counting_throttle():
            if module.errored:
                self.throttled_after_error += 1
            return await real_throttle()

        module_test.monkeypatch.setattr(module, "_throttle", counting_throttle)

    def check(self, module_test, events):
        assert module_test.module.errored is True
        assert self.throttled_after_error == 0, (
            f"{self.throttled_after_error} requests still waited on the throttle after the module errored"
        )


class TestShodan_Enterprise_EventsDuringBatch(ModuleTestBase):
    """An IP queued while a batch is being handled must still be looked up, and the scan must finish."""

    targets = ["1.2.3.0/24"]
    seeds = [f"1.2.3.{i}" for i in range(40, 46)]
    module_name = "shodan_enterprise"
    config_overrides = {
        "modules": {"shodan_enterprise": {"api_key": "deadbeef", "requests_per_second": 2, "search_prefilter": False}},
    }

    async def setup_after_prep(self, module_test):
        module = module_test.module
        self.injected = False

        async def _cb(request):
            ip = str(request.url).split("/shodan/host/")[-1].split("?")[0]
            if not self.injected:
                # a new in-scope IP arrives while the batch is still being handled
                self.injected = True
                late = module.scan.make_event("1.2.3.31", "IP_ADDRESS", parent=module.scan.root_event)
                late.scope_distance = 0
                await module.queue_event(late)
            port = 8443 if ip == "1.2.3.31" else 443
            return MockResponse(status_code=200, json=host_record(ip, port=port))

        module_test.blasthttp_mock.add_callback(_cb, url=None)

    def check(self, module_test, events):
        assert self.injected
        ports = {e.data for e in events if e.type == "OPEN_TCP_PORT"}
        assert "1.2.3.31:8443" in ports, f"the IP queued mid-batch was never looked up: {sorted(ports)}"


class TestShodan_Enterprise_Hostnames(ModuleTestBase):
    """The host record's hostnames come out as DNS_NAME, the way shodan_idb reports them."""

    targets = ["198.51.100.10", "198.51.100.11", "198.51.100.12", "example.com"]
    module_name = "shodan_enterprise"
    config_overrides = {
        "modules": {
            "shodan_enterprise": {"api_key": "deadbeef", "requests_per_second": 1000, "search_prefilter": False}
        },
        "dns": {"minimal": True},
    }

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "example.com": {"A": ["198.51.100.20"]},
                "mail.example.com": {"A": ["198.51.100.10"]},
                "autodiscover.example.com": {"A": ["198.51.100.10"]},
                "only.example.com": {"A": ["198.51.100.11"]},
            }
        )
        records = {
            # case and trailing-dot duplicates, the IP itself, an empty string and a wildcard
            "198.51.100.10": {
                "hostnames": [
                    "Mail.Example.com.",
                    "mail.example.com",
                    "autodiscover.example.com",
                    "198.51.100.10",
                    "",
                    "*.dev.example.com",
                ],
                **host_record("198.51.100.10"),
            },
            # names but no banners
            "198.51.100.11": {"hostnames": ["only.example.com"], "data": []},
            # no hostnames key
            "198.51.100.12": host_record("198.51.100.12"),
        }

        async def _cb(request):
            ip = str(request.url).split("/shodan/host/")[-1].split("?")[0]
            if ip in records:
                return MockResponse(status_code=200, json=records[ip])
            return MockResponse(status_code=404, json={"error": "No information available for that IP."})

        module_test.blasthttp_mock.add_callback(_cb, url=None)

        # count what the module emits before the scan's dedup
        self.emitted_names = []
        real_emit = module_test.module.emit_event

        async def counting_emit(*args, **kwargs):
            if len(args) > 1 and args[1] == "DNS_NAME":
                self.emitted_names.append(args[0])
            return await real_emit(*args, **kwargs)

        module_test.monkeypatch.setattr(module_test.module, "emit_event", counting_emit)

    def check(self, module_test, events):
        assert sorted(self.emitted_names) == ["autodiscover.example.com", "mail.example.com", "only.example.com"], (
            f"module emitted {self.emitted_names}"
        )
        names = [e for e in events if e.type == "DNS_NAME" and e.module.name == "shodan_enterprise"]
        found = sorted(e.data for e in names)
        # "*.dev.example.com" must be skipped, not turned into dev.example.com
        assert found == ["autodiscover.example.com", "mail.example.com", "only.example.com"], found
        for e in names:
            assert e.parent.type == "IP_ADDRESS", f"{e.data} should hang off its IP, got {e.parent.type}"
        by_name = {e.data: str(e.parent.data) for e in names}
        assert by_name["only.example.com"] == "198.51.100.11"
        ports = {e.data for e in events if e.type == "OPEN_TCP_PORT"}
        assert ports == {"198.51.100.10:443", "198.51.100.12:443"}, ports
        assert module_test.module.errored is False


class TestShodan_Enterprise_HostnameResolvesToNewIP(ModuleTestBase):
    """A hostname from Shodan that resolves to a new in-scope IP is looked up too, and the scan finishes.

    Regression test: this hung while the module buffered IPs until finish().
    """

    # 1.2.3.31 is not a seed: it is first seen when b.example.com, found on 1.2.3.30, resolves
    targets = ["b.example.com", "1.2.3.0/24"]
    seeds = ["1.2.3.30"] + [f"1.2.3.{i}" for i in range(40, 46)]
    module_name = "shodan_enterprise"
    config_overrides = {
        "modules": {"shodan_enterprise": {"api_key": "deadbeef", "requests_per_second": 2, "search_prefilter": False}},
        # A records must become IP_ADDRESS events
        "dns": {"minimal": False},
    }

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "a.example.com": {"A": ["1.2.3.30"]},
                "b.example.com": {"A": ["1.2.3.31"]},
            }
        )
        records = {
            "1.2.3.30": {"hostnames": ["b.example.com"], **host_record("1.2.3.30")},
            "1.2.3.31": host_record("1.2.3.31", port=8443),
        }

        async def _cb(request):
            ip = str(request.url).split("/shodan/host/")[-1].split("?")[0]
            if ip in records:
                return MockResponse(status_code=200, json=records[ip])
            return MockResponse(status_code=404, json={"error": "No information available for that IP."})

        module_test.blasthttp_mock.add_callback(_cb, url=None)

    def check(self, module_test, events):
        ports = {e.data for e in events if e.type == "OPEN_TCP_PORT" and e.module.name == "shodan_enterprise"}
        assert ports == {"1.2.3.30:443", "1.2.3.31:8443"}, ports


# The tests below call handle_batch() directly: in a scan, how IPs split into batches depends on timing.


@pytest.fixture
async def shodan_module():
    """Build a set-up shodan_enterprise module with the given module and web config."""
    from bbot.scanner import Scanner

    scans = []

    async def make(web=None, **module_config):
        config = {
            "modules": {"shodan_enterprise": {"api_key": "deadbeef", "requests_per_second": 1000, **module_config}},
            "web": {"api_retries": 0, **(web or {})},
        }
        scan = Scanner("198.51.100.0/24", modules=["shodan_enterprise"], config=config)
        await scan._prep()
        scans.append(scan)
        return scan.modules["shodan_enterprise"]

    yield make
    for scan in scans:
        await scan._cleanup()


class ShodanApi:
    """Answers count and host requests; records each one. ``count_status`` other than 200 fails every count."""

    def __init__(self, blasthttp_mock, known, count_status=200, host_record=None):
        self.known = set(known)
        self.count_status = count_status
        self.host_record = host_record or (lambda ip: {"data": [{"ip_str": ip, "port": 80, "transport": "tcp"}]})
        self.counts = []
        self.lookups = []
        blasthttp_mock.add_callback(self._cb, url=None)

    async def _cb(self, request):
        url = urlparse(str(request.url))
        if url.path == "/shodan/host/count":
            params = {k: v[0] for k, v in parse_qs(url.query).items()}
            self.counts.append(params)
            if self.count_status == 429:
                return MockResponse(status_code=429, json={"error": "rate limited"}, headers={"Retry-After": "1"})
            if self.count_status != 200:
                return MockResponse(status_code=self.count_status, text="<html><title>Just a moment...</title></html>")
            asked = params["query"].removeprefix("ip:").split(",")
            return MockResponse(status_code=200, json=count_response(*[ip for ip in asked if ip in self.known]))
        ip = url.path.removeprefix("/shodan/host/")
        self.lookups.append(ip)
        if ip not in self.known:
            return MockResponse(status_code=404, json={"error": "No information available for that IP."})
        return MockResponse(status_code=200, json=self.host_record(ip))


async def run_batch(module, ips):
    """Send one batch of IP_ADDRESS events through handle_batch(). Returns {ip: event} and the emitted events."""
    emitted = []

    async def capture(event, **kwargs):
        emitted.append(event)

    module.queue_outgoing_event = capture
    scan = module.scan
    batch = {ip: scan.make_event(ip, "IP_ADDRESS", parent=scan.root_event) for ip in ips}
    await module.handle_batch(*batch.values())
    return batch, emitted


def ports_of(emitted):
    return {e.data for e in emitted if e.type == "OPEN_TCP_PORT"}


async def test_shodan_enterprise_count_prefilter_skips_unknown(shodan_module, blasthttp_mock):
    """One free count query per batch; IPs it does not return never reach the host endpoint."""
    module = await shodan_module()
    ips = ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
    api = ShodanApi(blasthttp_mock, known=["198.51.100.2"])

    batch, emitted = await run_batch(module, ips)

    assert len(api.counts) == 1, api.counts
    count = api.counts[0]
    assert count["key"] == "deadbeef"
    assert count["query"] == "ip:" + ",".join(ips)
    # the facet is as large as the chunk, so every known IP fits in one answer
    assert count["facets"] == "ip:3"
    assert api.lookups == ["198.51.100.2"], api.lookups
    assert ports_of(emitted) == {"198.51.100.2:80"}
    port = next(e for e in emitted if e.type == "OPEN_TCP_PORT")
    assert port.parent is batch["198.51.100.2"], "the port should hang off the IP event it was found for"


async def test_shodan_enterprise_single_ip_skips_count(shodan_module, blasthttp_mock):
    """A count plus a lookup costs more than the lookup alone."""
    module = await shodan_module()
    api = ShodanApi(blasthttp_mock, known=["198.51.100.1"])

    _, emitted = await run_batch(module, ["198.51.100.1"])

    assert api.counts == []
    assert api.lookups == ["198.51.100.1"]
    assert ports_of(emitted) == {"198.51.100.1:80"}


async def test_shodan_enterprise_prefilter_disabled(shodan_module, blasthttp_mock):
    """search_prefilter=false skips the count query and looks up every IP."""
    module = await shodan_module(search_prefilter=False)
    ips = ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
    api = ShodanApi(blasthttp_mock, known=["198.51.100.2"])

    _, emitted = await run_batch(module, ips)

    assert api.counts == []
    assert sorted(api.lookups) == ips
    assert ports_of(emitted) == {"198.51.100.2:80"}


async def test_shodan_enterprise_count_failure_falls_back(shodan_module, blasthttp_mock):
    """A failed count query degrades to direct lookups of its chunk, never drops the IPs."""
    module = await shodan_module()
    ips = ["198.51.100.1", "198.51.100.2"]
    api = ShodanApi(blasthttp_mock, known=ips, count_status=403)

    _, emitted = await run_batch(module, ips)

    assert len(api.counts) == 1
    assert sorted(api.lookups) == ips
    assert ports_of(emitted) == {f"{ip}:80" for ip in ips}
    # one failure is not yet a wall
    assert module.search_prefilter is True


async def test_shodan_enterprise_count_wall_disables_prefilter(shodan_module, blasthttp_mock):
    """A wall in front of the count endpoint costs two requests, not one per chunk."""
    module = await shodan_module(search_chunk_size=1)
    ips = [f"198.51.100.{i}" for i in range(1, 6)]
    api = ShodanApi(blasthttp_mock, known=ips, count_status=403)

    _, emitted = await run_batch(module, ips)

    assert len(api.counts) == module._max_search_failures, api.counts
    assert module.search_prefilter is False, "prefilter should have turned itself off"
    assert module.errored is False, "a wall in front of the count endpoint took the whole module down"
    assert sorted(api.lookups) == ips
    assert ports_of(emitted) == {f"{ip}:80" for ip in ips}


async def test_shodan_enterprise_count_rate_limit_keeps_prefilter(shodan_module, blasthttp_mock):
    """A rate-limited count is not a wall: turning the prefilter off would add requests to a throttled key."""
    module = await shodan_module(search_chunk_size=1, web={"429_sleep_interval": 1, "429_max_sleep_interval": 1})
    ips = ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
    api = ShodanApi(blasthttp_mock, known=ips, count_status=429)

    _, emitted = await run_batch(module, ips)

    assert module.search_prefilter is True, "a rate limit was treated as a wall"
    assert len(api.counts) == len(ips), f"every chunk should still try the count, got {len(api.counts)}"
    assert ports_of(emitted) == {f"{ip}:80" for ip in ips}
    assert module.errored is False


async def test_shodan_enterprise_requests_at_scale(shodan_module, blasthttp_mock):
    """250 IPs, 30 known to Shodan: 3 count queries plus 30 lookups instead of 250 lookups."""
    module = await shodan_module()
    ips = [f"198.51.100.{i}" for i in range(250)]
    known = ips[:30]
    api = ShodanApi(blasthttp_mock, known=known)

    _, emitted = await run_batch(module, ips)

    assert [c["facets"] for c in api.counts] == ["ip:100", "ip:100", "ip:50"]
    assert sorted(api.lookups) == sorted(known)
    assert ports_of(emitted) == {f"{ip}:80" for ip in known}


def vuln_banner(ip, port, vulns):
    return {"ip_str": ip, "port": port, "transport": "tcp", "vulns": vulns}


async def test_shodan_enterprise_cvss_severity(shodan_module, blasthttp_mock):
    """Every CVE becomes a FINDING with a valid severity, whatever its CVSS looks like."""
    module = await shodan_module()
    ip = "198.51.100.1"
    record = {
        "data": [
            vuln_banner(
                ip,
                80,
                {
                    # a null score comes first: it must not cost the rest of the host
                    "CVE-2000-0001": {"cvss": None},
                    "CVE-2000-0002": {"cvss": 0.0},
                    "CVE-2000-0003": {},
                    "CVE-2000-0004": {"cvss": "n/a"},
                    "CVE-2000-0005": {"cvss_v3": 9.8, "cvss": 5.0, "cvss_v2": 4.0},
                    "CVE-2000-0006": {"cvss_v3": None, "cvss": 5.0},
                    "CVE-2000-0007": {"cvss_v2": 7.2},
                },
            ),
            vuln_banner(
                ip,
                443,
                {
                    "CVE-2000-0010": {"cvss": 0.1},
                    "CVE-2000-0011": {"cvss": 4.0},
                    "CVE-2000-0012": {"cvss": 7.0},
                    "CVE-2000-0013": {"cvss": 9.0},
                    "CVE-2000-0014": {"cvss": 3.9},
                },
            ),
        ]
    }
    ShodanApi(blasthttp_mock, known=[ip], host_record=lambda _: record)

    _, emitted = await run_batch(module, [ip])

    findings = {e.data["cves"][0]: e.data for e in emitted if e.type == "FINDING"}
    severities = {cve: f["severity"] for cve, f in findings.items()}
    assert severities == {
        "CVE-2000-0001": "INFO",
        "CVE-2000-0002": "INFO",
        "CVE-2000-0003": "INFO",
        "CVE-2000-0004": "INFO",
        "CVE-2000-0005": "CRITICAL",
        "CVE-2000-0006": "MEDIUM",
        "CVE-2000-0007": "HIGH",
        "CVE-2000-0010": "LOW",
        "CVE-2000-0011": "MEDIUM",
        "CVE-2000-0012": "HIGH",
        "CVE-2000-0013": "CRITICAL",
        "CVE-2000-0014": "LOW",
    }, severities
    # the score explains the severity; no score, no suffix
    assert findings["CVE-2000-0001"]["description"] == "CVE-2000-0001 on 80/tcp"
    assert findings["CVE-2000-0002"]["description"] == "CVE-2000-0002 on 80/tcp (CVSS 0.0)"
    assert findings["CVE-2000-0005"]["description"] == "CVE-2000-0005 on 80/tcp (CVSS 9.8)"
    assert findings["CVE-2000-0012"]["description"] == "CVE-2000-0012 on 443/tcp (CVSS 7.0)"
    # the banner after the null score was still emitted
    assert ports_of(emitted) == {f"{ip}:80", f"{ip}:443"}
