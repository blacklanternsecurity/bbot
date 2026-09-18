from .base import ModuleTestBase


class FakeResponse:
    """Stand-in for an httpx response, covering what _request() reads off one."""

    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = str(payload)

    def json(self):
        return self._payload


def search_response(*ips, total=None):
    """A /shodan/host/search body. Phase 1 only reads ip_str and total."""
    matches = [{"ip_str": ip} for ip in ips]
    return {"matches": matches, "total": total if total is not None else len(matches)}


def mock_search(module_test, payload, status_code=200):
    """Replace phase 1's transport.

    The module reaches /shodan/host/search over httpx rather than BBOT's engine,
    because Cloudflare 403s the latter -- so blasthttp_mock cannot see that call
    and it has to be patched on the module itself.
    """

    async def _send(url):
        return FakeResponse(payload, status_code=status_code) if payload is not None else None

    module_test.monkeypatch.setattr(module_test.module, "_send_via_httpx", _send)


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
        mock_search(module_test, search_response("8.8.8.8"))

    def check(self, module_test, events):
        tcp_ports = [e.data for e in events if e.type == "OPEN_TCP_PORT"]
        udp_ports = [e.data for e in events if e.type == "OPEN_UDP_PORT"]
        assert any("8.8.8.8:53" in str(p) for p in tcp_ports), "TCP port 53 not detected"
        # The UDP banner is why phase 2 exists: the search index withholds it.
        assert any("8.8.8.8:53" in str(p) for p in udp_ports), "UDP port 53 not detected"

        finding_events = [e for e in events if e.type == "FINDING"]
        finding_map = {e.data.get("description"): e.data.get("severity") for e in finding_events}
        assert "CVE-2021-12345" in finding_map
        assert finding_map["CVE-2021-12345"] == "HIGH"
        assert "CVE-2020-00001" in finding_map
        assert finding_map["CVE-2020-00001"] == "LOW"

        # Shodan attaches vulns to a banner, not to the host, so the finding
        # must descend from that banner's port event -- that is how BBOT records
        # which service a CVE belongs to.
        by_cve = {e.data.get("description"): e for e in finding_events}
        finding = by_cve["CVE-2021-12345"]
        assert finding.parent.type == "OPEN_TCP_PORT", (
            f"FINDING should hang off the port it was found on, got {finding.parent.type}"
        )
        assert "8.8.8.8:53" in str(finding.parent.data)
        # and the CVE belongs in the field meant for it
        assert finding.data.get("cves") == ["CVE-2021-12345"]
        # The port is not on the finding itself -- BBOT offers no supported way
        # to put it there -- so the parent chain above is the whole record of
        # which service is affected. Pinned so that an upstream fix is noticed.
        assert finding.port is None, (
            f"finding.port is now {finding.port}; BBOT may have gained port support -- "
            "drop the parent-chain workaround if so"
        )

        tech_events = [e for e in events if e.type == "TECHNOLOGY"]
        tech_names = {e.data.get("technology") for e in tech_events}
        assert "cpe:/a:google:dns" in tech_names
        assert "google public dns" in tech_names
        assert "openssl" in tech_names
        assert "nginx" in tech_names

        # Technologies come from the same banner and follow the same rule.
        # Which transport wins is a dedup race -- the TCP and UDP banners carry
        # the same technology on the same port -- so assert only that the parent
        # is the port, not which one.
        tech_parents = {e.parent.type for e in tech_events}
        assert tech_parents <= {"OPEN_TCP_PORT", "OPEN_UDP_PORT"}, (
            f"TECHNOLOGY should hang off a port event, got {tech_parents}"
        )


class TestShodan_Enterprise_PrefilterSkipsUnknown(ModuleTestBase):
    """An IP the search does not return must never reach the host endpoint.

    This is where the batching pays off: on real target sets most IPs are unknown
    to Shodan, and each one skipped here is one rate-limited request saved.
    """

    targets = ["8.8.8.8"]
    module_name = "shodan_enterprise"
    config_overrides = {"modules": {"shodan_enterprise": {"api_key": "deadbeef"}}}

    async def setup_before_prep(self, module_test):
        # Registered so that a phase 2 request would succeed -- the assertion is
        # that it never happens.
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
    """A failed search must degrade to direct lookups, never drop the IPs.

    Cloudflare returned 403 on this endpoint during development; the fallback is
    what kept that scan complete instead of silently empty.
    """

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
    """search_prefilter=false skips phase 1 entirely and queries every IP."""

    targets = ["8.8.8.8"]
    module_name = "shodan_enterprise"
    config_overrides = {"modules": {"shodan_enterprise": {"api_key": "deadbeef", "search_prefilter": False}}}

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://api.shodan.io/shodan/host/8.8.8.8?key=deadbeef",
            json=host_response_8_8_8_8,
        )

    async def setup_after_prep(self, module_test):
        # Deliberately not mocked: with the prefilter off nothing should call it.
        async def _fail(url):
            raise AssertionError("search must not be called when search_prefilter is false")

        module_test.monkeypatch.setattr(module_test.module, "_send_via_httpx", _fail)

    def check(self, module_test, events):
        assert any(e.type == "OPEN_TCP_PORT" and "8.8.8.8:53" in str(e.data) for e in events)
        assert any(e.type == "OPEN_UDP_PORT" and "8.8.8.8:53" in str(e.data) for e in events)


class TestShodan_Enterprise_BatchingAtScale(ModuleTestBase):
    """The batching claim, measured: 250 IPs must not cost 250 lookups.

    A handful of targets never exercises chunking, so this feeds enough IPs to
    span several search queries and counts both transports. Shodan knows 30 of
    the 250, so the run should cost 3 searches (ceil(250/100)) plus 30 lookups --
    33 requests where the unbatched module would have made 250.
    """

    _all_ips = [f"198.51.100.{i}" for i in range(250)]
    _known_ips = _all_ips[:30]

    targets = _all_ips
    module_name = "shodan_enterprise"
    config_overrides = {
        "modules": {"shodan_enterprise": {"api_key": "deadbeef", "requests_per_second": 1000}},
        "dns": {"minimal": True},
    }

    async def setup_before_prep(self, module_test):
        for ip in self._known_ips:
            module_test.blasthttp_mock.add_response(
                url=f"https://api.shodan.io/shodan/host/{ip}?key=deadbeef",
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

    async def setup_after_prep(self, module_test):
        self.search_calls = []
        self.lookup_calls = []
        known = set(self._known_ips)

        async def fake_search(url):
            self.search_calls.append(url)
            # Answer with whichever known IPs this particular chunk asked about,
            # so the module's per-chunk bookkeeping is exercised rather than bypassed.
            asked = url.split("query=")[-1]
            hits = [ip for ip in known if ip.replace(".", "%2E") in asked or ip in asked]
            return FakeResponse(search_response(*hits))

        real_bbot_send = module_test.module._send_via_bbot

        async def counting_bbot_send(url):
            self.lookup_calls.append(url)
            return await real_bbot_send(url)

        module_test.monkeypatch.setattr(module_test.module, "_send_via_httpx", fake_search)
        module_test.monkeypatch.setattr(module_test.module, "_send_via_bbot", counting_bbot_send)

    def check(self, module_test, events):
        searches = len(self.search_calls)
        lookups = len(self.lookup_calls)
        module_test.log.critical(
            f"BATCHING: {len(self._all_ips)} IPs -> {searches} search(es) + {lookups} lookup(s) "
            f"= {searches + lookups} requests (unbatched would be {len(self._all_ips)})"
        )

        # Chunking: 250 IPs at search_chunk_size=100 cannot fit in fewer than 3
        # queries. Batches may arrive split, so allow more, but never one per IP.
        assert searches >= 3, f"expected at least 3 search queries, got {searches}"
        assert searches < 50, f"search was not batching: {searches} queries for 250 IPs"

        # The point of the prefilter: IPs Shodan does not know cost no lookup.
        assert lookups <= len(self._known_ips) * 2, (
            f"expected ~{len(self._known_ips)} lookups, got {lookups} -- prefilter did not skip unknown IPs"
        )
        assert lookups + searches < 250, f"{lookups + searches} requests for 250 IPs is no better than unbatched"

        # And the data still arrives.
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
