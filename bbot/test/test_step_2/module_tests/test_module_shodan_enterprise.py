import inspect
import time

from bbot.test.mock_blasthttp import MockResponse

from .base import ModuleTestBase


def search_response(*ips, total=None):
    """A /shodan/host/search body. The module only reads ip_str and total."""
    matches = [{"ip_str": ip} for ip in ips]
    return {"matches": matches, "total": total if total is not None else len(matches)}


def mock_search(module_test, payload, status_code=200, record=None):
    """Answer /shodan/host/search through BBOT's own HTTP mock. ``payload=None`` serves a 403 interstitial."""

    async def _cb(request):
        url = str(request.url)
        if record is not None:
            record.append(url)
        if payload is None:
            return MockResponse(status_code=403, text="<html><title>Just a moment...</title></html>")
        return MockResponse(status_code=status_code, json=payload)

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
    """The full two-phase path: batched search, then a per-IP lookup."""

    targets = ["8.8.8.8"]
    config_overrides = {"modules": {"shodan_enterprise": {"api_key": "deadbeef"}}}

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://api.shodan.io/shodan/host/8.8.8.8?key=deadbeef",
            json=host_response_8_8_8_8,
        )

    async def setup_after_prep(self, module_test):
        self.search_calls = []
        mock_search(module_test, search_response("8.8.8.8"), record=self.search_calls)

    def check(self, module_test, events):
        # blasthttp_mock only sees requests made through helpers.request()
        assert self.search_calls, "the search never reached BBOT's HTTP layer"
        assert "/shodan/host/search" in self.search_calls[0]

        tcp_ports = [e.data for e in events if e.type == "OPEN_TCP_PORT"]
        udp_ports = [e.data for e in events if e.type == "OPEN_UDP_PORT"]
        assert any("8.8.8.8:53" in str(p) for p in tcp_ports), "TCP port 53 not detected"
        # the search index withholds this UDP banner, so only the direct lookup finds it
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
        # the service is named in the finding itself
        assert finding.data["description"] == "CVE-2021-12345 on 53/tcp", (
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

        # the per-IP bookkeeping must not outlive the batch
        assert module_test.module._parents == {}, (
            f"_parents still holds {len(module_test.module._parents)} events after the scan"
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
        mock_search(module_test, search_response("8.8.8.8"))

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        descriptions = sorted(e.data["description"] for e in findings)
        assert descriptions == ["CVE-2021-12345 on 443/tcp", "CVE-2021-12345 on 80/tcp"], (
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
        mock_search(module_test, search_response("8.8.8.8"))

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert len(findings) == 1, f"expected the finding to survive a portless banner, got {len(findings)}"
        assert findings[0].data["description"] == "CVE-2021-12345", findings[0].data["description"]
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
            if "/shodan/host/search" in url:
                return MockResponse(status_code=200, json=search_response("8.8.8.8"))
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


class TestShodan_Enterprise_SearchStopsWhenChunkResolved(ModuleTestBase):
    """Stop paging as soon as every IP in the chunk is accounted for (each page costs a query credit)."""

    _ips = ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
    targets = _ips
    module_name = "shodan_enterprise"
    config_overrides = {
        "modules": {"shodan_enterprise": {"api_key": "deadbeef", "requests_per_second": 1000}},
        "dns": {"minimal": True},
    }

    async def setup_before_prep(self, module_test):
        for ip in self._ips:
            module_test.blasthttp_mock.add_response(
                url=f"https://api.shodan.io/shodan/host/{ip}?key=deadbeef",
                json={"data": [{"ip_str": ip, "port": 80, "transport": "tcp", "vulns": {}}]},
            )

    async def setup_after_prep(self, module_test):
        self.search_calls = []
        # a full page: our three IPs plus filler banners from other hosts, and a
        # total that promises four more pages
        filler = [f"203.0.113.{i}" for i in range(97)]
        mock_search(
            module_test,
            search_response(*(self._ips + filler), total=500),
            record=self.search_calls,
        )

    def check(self, module_test, events):
        assert len(self.search_calls) == 1, (
            f"chunk was fully resolved on page 1 but the module paged {len(self.search_calls)} times"
        )
        ports = {e.data for e in events if e.type == "OPEN_TCP_PORT"}
        assert ports == {f"{ip}:80" for ip in self._ips}, ports


class TestShodan_Enterprise_SearchWallDisablesPrefilter(ModuleTestBase):
    """A wall in front of the search endpoint costs two requests, not one per chunk."""

    _ips = [f"198.51.100.{i}" for i in range(1, 6)]
    targets = _ips
    module_name = "shodan_enterprise"
    config_overrides = {
        "modules": {
            "shodan_enterprise": {
                "api_key": "deadbeef",
                "requests_per_second": 1000,
                "search_chunk_size": 1,
            }
        },
        "web": {"api_retries": 0},
        "dns": {"minimal": True},
    }

    async def setup_before_prep(self, module_test):
        for ip in self._ips:
            module_test.blasthttp_mock.add_response(
                url=f"https://api.shodan.io/shodan/host/{ip}?key=deadbeef",
                json={"data": [{"ip_str": ip, "port": 80, "transport": "tcp", "vulns": {}}]},
            )

    async def setup_after_prep(self, module_test):
        self.search_calls = []
        mock_search(module_test, None, record=self.search_calls)  # 403, every time

    def check(self, module_test, events):
        assert len(self.search_calls) == module_test.module._max_search_failures, (
            f"prefilter kept hitting the wall: {len(self.search_calls)} search attempts for {len(self._ips)} IPs"
        )
        assert module_test.module.search_prefilter is False, "prefilter should have turned itself off"
        assert module_test.module.errored is False, "a wall in front of search took the whole module down"
        ports = {e.data for e in events if e.type == "OPEN_TCP_PORT"}
        assert ports == {f"{ip}:80" for ip in self._ips}, ports


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

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://api.shodan.io/shodan/host/8.8.8.8?key=deadbeef",
            json=host_response_8_8_8_8,
        )

    async def setup_after_prep(self, module_test):
        self.seen_agents = []

        async def _cb(request):
            headers = {k.lower(): v for k, v in dict(request.headers).items()}
            self.seen_agents.append(headers.get("user-agent"))
            return MockResponse(status_code=200, json=search_response("8.8.8.8"))

        module_test.blasthttp_mock.add_callback(_cb, url=None)

    def check(self, module_test, events):
        assert self.seen_agents, "the search never reached BBOT's HTTP layer"
        for ua in self.seen_agents:
            assert ua, "API request left User-Agent to the scan config"
            assert "Mozilla" not in ua, f"API request carried a browser-like User-Agent: {ua!r}"
        assert any(e.type == "OPEN_TCP_PORT" for e in events)


class TestShodan_Enterprise_PrefilterSkipsUnknown(ModuleTestBase):
    """An IP the search does not return must never reach the host endpoint."""

    targets = ["8.8.8.8"]
    module_name = "shodan_enterprise"
    config_overrides = {"modules": {"shodan_enterprise": {"api_key": "deadbeef"}}}

    async def setup_before_prep(self, module_test):
        # registered so a lookup would succeed; the check asserts it never happens
        module_test.blasthttp_mock.add_response(
            url="https://api.shodan.io/shodan/host/8.8.8.8?key=deadbeef",
            json=host_response_8_8_8_8,
        )

    async def setup_after_prep(self, module_test):
        mock_search(module_test, search_response())  # no matches

    def check(self, module_test, events):
        assert not any(e.type in ("OPEN_TCP_PORT", "OPEN_UDP_PORT", "FINDING") for e in events), (
            "Should not have queried an IP the search prefilter found nothing for"
        )


class TestShodan_Enterprise_SearchFailureFallsBack(ModuleTestBase):
    """A failed search must degrade to direct lookups, never drop the IPs."""

    targets = ["8.8.8.8"]
    module_name = "shodan_enterprise"
    config_overrides = {"modules": {"shodan_enterprise": {"api_key": "deadbeef"}}}

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://api.shodan.io/shodan/host/8.8.8.8?key=deadbeef",
            json=host_response_8_8_8_8,
        )

    async def setup_after_prep(self, module_test):
        mock_search(module_test, None)  # transport failure

    def check(self, module_test, events):
        assert any(e.type == "OPEN_TCP_PORT" and "8.8.8.8:53" in str(e.data) for e in events), (
            "Should have fallen back to a direct lookup when the search failed"
        )


class TestShodan_Enterprise_PrefilterDisabled(ModuleTestBase):
    """search_prefilter=false skips the search and queries every IP."""

    targets = ["8.8.8.8"]
    module_name = "shodan_enterprise"
    config_overrides = {"modules": {"shodan_enterprise": {"api_key": "deadbeef", "search_prefilter": False}}}

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://api.shodan.io/shodan/host/8.8.8.8?key=deadbeef",
            json=host_response_8_8_8_8,
        )

    async def setup_after_prep(self, module_test):
        self.search_calls = []
        mock_search(module_test, search_response("8.8.8.8"), record=self.search_calls)

    def check(self, module_test, events):
        assert self.search_calls == [], (
            f"search must not be called when search_prefilter is false: {self.search_calls}"
        )
        assert any(e.type == "OPEN_TCP_PORT" and "8.8.8.8:53" in str(e.data) for e in events)
        assert any(e.type == "OPEN_UDP_PORT" and "8.8.8.8:53" in str(e.data) for e in events)


class TestShodan_Enterprise_BatchingAtScale(ModuleTestBase):
    """250 IPs, 30 known to Shodan: about 3 searches plus 30 lookups instead of 250 lookups."""

    _all_ips = [f"198.51.100.{i}" for i in range(250)]
    _known_ips = _all_ips[:30]

    targets = _all_ips
    module_name = "shodan_enterprise"
    config_overrides = {
        "modules": {"shodan_enterprise": {"api_key": "deadbeef", "requests_per_second": 1000}},
        "dns": {"minimal": True},
    }

    async def setup_after_prep(self, module_test):
        self.search_calls = []
        self.lookup_calls = []
        known = set(self._known_ips)

        async def _cb(request):
            url = str(request.url)
            if "/shodan/host/search" in url:
                self.search_calls.append(url)
                # answer with whichever known IPs this chunk asked about
                asked = url.split("query=")[-1]
                hits = [ip for ip in known if ip.replace(".", "%2E") in asked or ip in asked]
                return MockResponse(status_code=200, json=search_response(*hits))
            self.lookup_calls.append(url)
            ip = url.split("/shodan/host/")[-1].split("?")[0]
            if ip not in known:
                return MockResponse(status_code=404, json={"error": "No information available for that IP."})
            return MockResponse(
                status_code=200,
                json={
                    "data": [
                        {
                            "ip_str": ip,
                            "port": 80,
                            "transport": "tcp",
                            "tags": [],
                            "cpe": [],
                            "cpe23": [],
                            "http": {},
                            "vulns": {},
                        }
                    ]
                },
            )

        module_test.blasthttp_mock.add_callback(_cb, url=None)

    def check(self, module_test, events):
        searches = len(self.search_calls)
        lookups = len(self.lookup_calls)
        module_test.log.critical(
            f"BATCHING: {len(self._all_ips)} IPs -> {searches} search(es) + {lookups} lookup(s) "
            f"= {searches + lookups} requests (unbatched would be {len(self._all_ips)})"
        )

        # 250 IPs at search_chunk_size=100 need at least 3 queries; batches may arrive split
        assert searches >= 3, f"expected at least 3 search queries, got {searches}"
        assert searches < 50, f"search was not batching: {searches} queries for 250 IPs"

        # IPs Shodan does not know cost no lookup
        assert lookups <= len(self._known_ips) * 2, (
            f"expected ~{len(self._known_ips)} lookups, got {lookups} (prefilter did not skip unknown IPs)"
        )
        assert lookups + searches < 250, f"{lookups + searches} requests for 250 IPs is no better than unbatched"

        ports = {e.data for e in events if e.type == "OPEN_TCP_PORT"}
        assert f"{self._known_ips[0]}:80" in ports
        assert not any(e.data.startswith("198.51.100.200:") for e in events if e.type == "OPEN_TCP_PORT"), (
            "emitted a port for an IP the search prefilter never returned"
        )


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
        mock_search(module_test, search_response("1.1.1.1"))

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
        mock_search(module_test, search_response("1.1.1.1"))

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


class TestShodan_Enterprise_SearchRateLimitKeepsPrefilter(ModuleTestBase):
    """A rate-limited search is not a wall: the prefilter must stay on.

    Turning it off would multiply the requests sent to a key that is already
    being throttled.
    """

    _ips = ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
    targets = _ips
    module_name = "shodan_enterprise"
    config_overrides = {
        "modules": {"shodan_enterprise": {"api_key": "deadbeef", "requests_per_second": 1000, "search_chunk_size": 1}},
        "web": {"api_retries": 0, "429_sleep_interval": 1, "429_max_sleep_interval": 1},
        "dns": {"minimal": True},
    }

    async def setup_after_prep(self, module_test):
        self.search_calls = 0

        async def _cb(request):
            url = str(request.url)
            if "/shodan/host/search" in url:
                self.search_calls += 1
                return MockResponse(status_code=429, json={"error": "rate limited"}, headers={"Retry-After": "1"})
            ip = url.split("/shodan/host/")[-1].split("?")[0]
            return MockResponse(status_code=200, json=host_record(ip))

        module_test.blasthttp_mock.add_callback(_cb, url=None)

    def check(self, module_test, events):
        assert module_test.module.search_prefilter is True, "a rate limit was treated as a wall"
        assert self.search_calls == len(self._ips), f"every chunk should still try search, got {self.search_calls}"
        ports = {e.data for e in events if e.type == "OPEN_TCP_PORT"}
        assert ports == {f"{ip}:443" for ip in self._ips}, ports
        assert module_test.module.errored is False


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


class TestShodan_Enterprise_EventsDuringFinish(ModuleTestBase):
    """An IP queued while finish() is running must still be looked up, and the scan must finish."""

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
                # a new in-scope IP arrives while finish() is still running
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
        assert "1.2.3.31:8443" in ports, f"the IP queued during finish() was never looked up: {sorted(ports)}"
