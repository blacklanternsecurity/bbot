from bbot.test.mock_blasthttp import MockResponse

from .base import ModuleTestBase


class FakeResponse:
    """Stand-in for a response object, covering what _request() reads off one."""

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


def mock_search(module_test, payload, status_code=200, record=None):
    """Answer /shodan/host/search through BBOT's own HTTP mock.

    Both phases go through helpers.request(), so the search is an ordinary BBOT
    request and blasthttp_mock sees it -- no module internals are patched. That
    the mock sees it at all is the assertion that the module has one transport.

    ``payload=None`` serves the Cloudflare interstitial this endpoint used to
    answer with: a 403, which _request() does not retry.
    """

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
        # blasthttp_mock only sees requests that went through helpers.request(),
        # so this is the assertion that the module has a single transport and
        # phase 1 is not slipping out through a client of its own.
        assert self.search_calls, "the search never reached BBOT's HTTP layer"
        assert "/shodan/host/search" in self.search_calls[0]

        tcp_ports = [e.data for e in events if e.type == "OPEN_TCP_PORT"]
        udp_ports = [e.data for e in events if e.type == "OPEN_UDP_PORT"]
        assert any("8.8.8.8:53" in str(p) for p in tcp_ports), "TCP port 53 not detected"
        # The UDP banner is why phase 2 exists: the search index withholds it.
        assert any("8.8.8.8:53" in str(p) for p in udp_ports), "UDP port 53 not detected"

        finding_events = [e for e in events if e.type == "FINDING"]
        # keyed on cves, the machine-readable field -- description is prose and
        # names the affected service, which is asserted separately below
        finding_map = {e.data["cves"][0]: e.data.get("severity") for e in finding_events}
        assert "CVE-2021-12345" in finding_map
        assert finding_map["CVE-2021-12345"] == "HIGH"
        assert "CVE-2020-00001" in finding_map
        assert finding_map["CVE-2020-00001"] == "LOW"

        # Shodan attaches vulns to a banner, not to the host, so the finding
        # must descend from that banner's port event -- that is how BBOT records
        # which service a CVE belongs to.
        by_cve = {e.data["cves"][0]: e for e in finding_events}
        finding = by_cve["CVE-2021-12345"]
        assert finding.parent.type == "OPEN_TCP_PORT", (
            f"FINDING should hang off the port it was found on, got {finding.parent.type}"
        )
        assert "8.8.8.8:53" in str(finding.parent.data)
        # and the CVE belongs in the field meant for it
        assert finding.data.get("cves") == ["CVE-2021-12345"]
        # ...and the affected service is named in the finding itself, not only in
        # the parent chain. A consumer that reads a FINDING on its own -- a report,
        # a CSV export, a dedup key -- must still be able to tell which service the
        # CVE is on.
        assert finding.data["description"] == "CVE-2021-12345 on 53/tcp", (
            f"finding should name the affected service, got {finding.data['description']!r}"
        )
        # event.port stays None -- BBOT offers no supported way to set it -- which
        # is exactly why the service is spelled out in description above. Pinned so
        # that an upstream fix is noticed.
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
        # TECHNOLOGY's validator takes only host/technology/url -- the "port" key
        # the module passes is dropped, so every banner of a host yields identical
        # data and BBOT keeps just the first. _emit_host walks host["data"] in
        # order, so "first" is the first banner, not a race: here that is the TCP
        # one. Recorded rather than worked around; see UPSTREAM.md.
        tech_parents = {e.parent.type for e in tech_events}
        assert tech_parents == {"OPEN_TCP_PORT"}, (
            f"TECHNOLOGY should hang off the first banner's port event, got {tech_parents}"
        )
        assert all("port" not in e.data for e in tech_events), (
            "TECHNOLOGY data should not carry a port key that the validator drops"
        )

        # the per-IP bookkeeping must not outlive the batch: _parents holds event
        # objects, and through them the whole graph above each IP
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
    """The same CVE on two services is two findings, not one.

    Shodan attaches vulns to a banner, so a host running the same vulnerable
    product on 80 and 443 reports the CVE on both. With the port living only in
    the parent chain, the two findings carry byte-identical data and BBOT dedups
    them down to one -- the second service silently disappears from the report.
    """

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
        # each one still points at its own port
        parents = sorted(str(e.parent.data) for e in findings)
        assert parents == ["8.8.8.8:443", "8.8.8.8:80"], parents


class TestShodan_Enterprise_FindingWithoutPort(ModuleTestBase):
    """A banner with no usable port still yields a finding, just without the suffix.

    Shodan occasionally returns a record with no port/transport. The finding must
    not be dropped, and must not claim a service it does not know.
    """

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
    """A 429 must actually move to the next API key.

    The key is baked into the URL, so cycling only works if the URL is rebuilt for
    each attempt -- otherwise cycle_api_key() rotates the list and the retry goes
    out under the old key anyway.
    """

    targets = ["8.8.8.8"]
    module_name = "shodan_enterprise"
    config_overrides = {
        "modules": {
            "shodan_enterprise": {
                "api_key": ["key1", "key2"],
                "requests_per_second": 1000,
                "retry_backoff": 0.01,
            }
        }
    }

    async def setup_after_prep(self, module_test):
        self.lookup_urls = []

        async def _send(url):
            if "/shodan/host/search" in url:
                return FakeResponse(search_response("8.8.8.8"))
            self.lookup_urls.append(url)
            if len(self.lookup_urls) == 1:
                return FakeResponse({"error": "rate limited"}, status_code=429)
            return FakeResponse(host_response_8_8_8_8)

        module_test.monkeypatch.setattr(module_test.module, "_send", _send)

    def check(self, module_test, events):
        assert len(self.lookup_urls) >= 2, f"expected a retry after the 429, got {self.lookup_urls}"
        assert "key=key1" in self.lookup_urls[0], self.lookup_urls[0]
        assert "key=key2" in self.lookup_urls[1], f"retry after 429 reused the rate-limited key: {self.lookup_urls[1]}"
        assert any(e.type == "OPEN_TCP_PORT" for e in events), "the retry should have succeeded"


class TestShodan_Enterprise_SearchStopsWhenChunkResolved(ModuleTestBase):
    """Stop paging as soon as every IP in the chunk is accounted for.

    Search bills one query credit per page and returns one match per *banner*, so
    a chunk of busy hosts can run to many pages. The prefilter only ever reads
    ip_str, so every page past the one that resolves the chunk is a credit spent
    for nothing.
    """

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
    """A wall in front of the search endpoint costs two requests, not one per chunk.

    This endpoint answered BBOT's engine with a Cloudflare interstitial once. It
    does not today, but a gateway, a WAF or exhausted query credits look the same
    from here: the prefilter must notice, step aside and let the scan finish on
    direct lookups.
    """

    _ips = [f"198.51.100.{i}" for i in range(1, 6)]
    targets = _ips
    module_name = "shodan_enterprise"
    config_overrides = {
        "modules": {
            "shodan_enterprise": {
                "api_key": "deadbeef",
                "requests_per_second": 1000,
                # one IP per query, so a per-chunk retry would be obvious
                "search_chunk_size": 1,
            }
        },
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
        # and nothing was lost: every IP still got looked up
        ports = {e.data for e in events if e.type == "OPEN_TCP_PORT"}
        assert ports == {f"{ip}:80" for ip in self._ips}, ports


class TestShodan_Enterprise_ApiRequestsAvoidBrowserUserAgent(ModuleTestBase):
    """API calls must not inherit a browser User-Agent from the scan config.

    web.user_agent shapes how *targets* see the scan. Sent to an authenticated
    vendor API it buys nothing and costs correctness: a browser User-Agent over a
    non-browser TLS stack is precisely what Cloudflare challenges, and
    api.shodan.io answers the search endpoint with a 403 interstitial. Measured
    against the live API -- Chrome/Edge UA: 403, "BBOT" or any non-browser UA: 200.
    """

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
            # the module must set one explicitly -- leaving it unset means
            # WebHelper fills in web.user_agent, which is the browser string above
            assert ua, "API request left User-Agent to the scan config"
            assert "Mozilla" not in ua, f"API request carried a browser-like User-Agent: {ua!r}"
        assert any(e.type == "OPEN_TCP_PORT" for e in events)


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
        self.search_calls = []
        mock_search(module_test, search_response("8.8.8.8"), record=self.search_calls)

    def check(self, module_test, events):
        assert self.search_calls == [], (
            f"search must not be called when search_prefilter is false: {self.search_calls}"
        )
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

        real_send = module_test.module._send

        async def counting_send(url):
            if "/shodan/host/search" in url:
                return await fake_search(url)
            self.lookup_calls.append(url)
            return await real_send(url)

        module_test.monkeypatch.setattr(module_test.module, "_send", counting_send)

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
