import json

from bbot.test.mock_blasthttp import MockResponse

from .base import ModuleTestBase

# The mock passes through localhost/127.0.0.1 (see _should_mock in conftest.py) so the
# API URL must be a non-local host, or requests hit a real server on port 3000.
API_URL = "http://rustywap-api.test:3000"

# bbot's test harness maps DNS to 127.0.0.88, and the module deliberately refuses
# private/loopback hosts, so these tests drive the module with synthetic public URLs
# rather than running a full scan against the local httpserver.
PUBLIC_HOST = "1.2.3.4"


def tech_entry(name, version=None, confidence=100, cpe=None, cves=None, kev=None, pocs=None):
    entry = {"technology": name, "confidence": confidence, "version": version}
    if cpe is not None:
        entry["cpe"] = cpe
    if cves is not None:
        entry["cves"] = cves
    if kev is not None:
        entry["kev"] = kev
    if pocs is not None:
        entry["pocs"] = pocs
    return entry


class RustywapTestBase(ModuleTestBase):
    module_name = "rustywap"
    modules_overrides = ["rustywap"]
    config_overrides = {"modules": {"rustywap": {"api_url": API_URL}}}

    async def setup_before_prep(self, module_test):
        # setup() runs during scan._prep(), so the health mock must exist before that
        module_test.blasthttp_mock.add_response(url=f"{API_URL}/health", json={"status": "ok"})

    def make_urls(self, module_test, count, host=PUBLIC_HOST):
        urls = [f"http://{host}/page{i}" for i in range(count)]
        events = [
            module_test.scan.make_event(u, "URL", parent=module_test.scan.root_event, tags=["status-200"])
            for u in urls
        ]
        return urls, events

    def capture_events(self, module_test):
        """Capture emit_event() calls instead of relying on the scan's event stream."""
        captured = []
        module = module_test.scan.modules["rustywap"]

        async def fake_emit_event(data, event_type, parent=None, context=None, **kwargs):
            captured.append((event_type, data))

        module_test.monkeypatch.setattr(module, "emit_event", fake_emit_event)
        return captured


class TestRustywap(RustywapTestBase):
    """Detections map onto TECHNOLOGY, and versions onto FINDINGs."""

    async def setup_after_prep(self, module_test):
        def batch_callback(request):
            body = json.loads(request.content)
            return MockResponse(
                status_code=200,
                json=[
                    {
                        "url": u,
                        "error": None,
                        "technologies": [
                            tech_entry("Nginx", version="1.28.0", cpe="cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"),
                            tech_entry("jQuery", version=None),
                        ],
                    }
                    for u in body["urls"]
                ],
            )

        module_test.blasthttp_mock.add_callback(batch_callback, url=f"{API_URL}/batch")
        module_test.requests = []

        module = module_test.scan.modules["rustywap"]
        original_submit = module._submit

        async def spy_submit(urls, depth=0):
            module_test.requests.append(list(urls))
            return await original_submit(urls, depth)

        module_test.monkeypatch.setattr(module, "_submit", spy_submit)

        module_test.captured = self.capture_events(module_test)
        _, events = self.make_urls(module_test, 1)
        await module.handle_batch(*events)

    def check(self, module_test, events):
        captured = module_test.captured
        techs = [d for t, d in captured if t == "TECHNOLOGY"]
        findings = [d for t, d in captured if t == "FINDING"]

        tech_names = {d["technology"] for d in techs}
        assert tech_names == {"nginx", "jquery"}, f"unexpected technologies: {tech_names}"

        # TECHNOLOGY's validator only permits {host, technology, url}; a version key would
        # be silently dropped, so versions must arrive as FINDINGs instead
        for d in techs:
            assert set(d) == {"technology", "url", "host"}, f"unexpected TECHNOLOGY keys: {sorted(d)}"

        version_findings = [d for d in findings if d["name"] == "Software Version - Nginx"]
        assert len(version_findings) == 1, f"expected one Nginx version FINDING, got {len(version_findings)}"
        assert "1.28.0" in version_findings[0]["description"]
        assert "cpe:2.3:a:f5:nginx" in version_findings[0]["description"]
        assert version_findings[0]["confidence"] == "CONFIRMED"

        # jQuery had no version, so no version FINDING
        assert not [d for d in findings if d["name"] == "Software Version - jQuery"]

        assert module_test.requests, "module never called _submit"


class TestRustywapRequestPayload(RustywapTestBase):
    """Config values are forwarded to the API in the request body."""

    config_overrides = {
        "modules": {
            "rustywap": {
                "api_url": API_URL,
                "concurrency": 25,
                "confidence": 70,
                "full_scan": True,
                "api_key": "sekrit",
            }
        }
    }

    async def setup_after_prep(self, module_test):
        module_test.bodies = []
        module_test.headers = []

        def batch_callback(request):
            module_test.bodies.append(json.loads(request.content))
            module_test.headers.append(dict(request.headers or {}))
            return MockResponse(status_code=200, json=[])

        module_test.blasthttp_mock.add_callback(batch_callback, url=f"{API_URL}/batch")

        module = module_test.scan.modules["rustywap"]
        _, events = self.make_urls(module_test, 2)
        await module.handle_batch(*events)

    def check(self, module_test, events):
        assert module_test.bodies, "module never called /batch"
        body = module_test.bodies[0]
        assert body["concurrency"] == 25
        assert body["confidence"] == 70
        assert body["full_scan"] is True
        assert len(body["urls"]) == 2

        headers = {k.lower(): v for k, v in module_test.headers[0].items()}
        assert headers.get("authorization") == "Bearer sekrit", f"missing bearer token: {headers}"


class TestRustywapBatching(RustywapTestBase):
    """More URLs than the server maximum must be split across multiple requests."""

    async def setup_after_prep(self, module_test):
        module_test.batch_sizes = []

        def batch_callback(request):
            body = json.loads(request.content)
            module_test.batch_sizes.append(len(body["urls"]))
            return MockResponse(
                status_code=200,
                json=[{"url": u, "error": None, "technologies": []} for u in body["urls"]],
            )

        module_test.blasthttp_mock.add_callback(batch_callback, url=f"{API_URL}/batch")

        module = module_test.scan.modules["rustywap"]
        _, events = self.make_urls(module_test, 250)
        # bbot hands handle_batch at most batch_size events, so mirror that here
        for start in range(0, len(events), module.batch_size):
            await module.handle_batch(*events[start : start + module.batch_size])

    def check(self, module_test, events):
        sizes = module_test.batch_sizes
        assert sizes, "module never called /batch"
        # 250 URLs at a clamped batch size of 100 => 100 + 100 + 50
        assert sizes == [100, 100, 50], f"unexpected batch split: {sizes}"
        assert max(sizes) <= 100, f"batch exceeded the server maximum: {sizes}"
        assert sum(sizes) == 250, f"URLs lost or duplicated: {sizes}"


class TestRustywapBatchSizeClamp(RustywapTestBase):
    """An operator batch_size above the server maximum is clamped rather than sent."""

    config_overrides = {"modules": {"rustywap": {"api_url": API_URL, "batch_size": 5000}}}

    async def setup_after_prep(self, module_test):
        pass

    def check(self, module_test, events):
        module = module_test.scan.modules["rustywap"]
        assert module.batch_size == 100, f"batch_size not clamped: {module.batch_size}"


class TestRustywapBisect(RustywapTestBase):
    """
    The API rejects an entire batch with 400 if any single URL fails its SSRF check.
    The module must halve the batch and still recover results from the clean half.
    """

    bad_url = f"http://{PUBLIC_HOST}/page3"

    async def setup_after_prep(self, module_test):
        module_test.request_count = 0
        bad_url = self.bad_url

        def batch_callback(request):
            module_test.request_count += 1
            body = json.loads(request.content)
            if bad_url in body["urls"]:
                return MockResponse(status_code=400, json={"error": f"SSRF check failed for {bad_url}"})
            return MockResponse(
                status_code=200,
                json=[
                    {"url": u, "error": None, "technologies": [tech_entry("Nginx", version="1.28.0")]}
                    for u in body["urls"]
                ],
            )

        module_test.blasthttp_mock.add_callback(batch_callback, url=f"{API_URL}/batch")

        module = module_test.scan.modules["rustywap"]
        urls, _ = self.make_urls(module_test, 8)
        module_test.results = await module._submit(urls)
        module_test.dropped = module._dropped_urls

    def check(self, module_test, events):
        returned = {r["url"] for r in module_test.results}
        assert self.bad_url not in returned, "the rejected URL should not appear in results"
        assert len(returned) == 7, f"expected 7 surviving URLs, got {len(returned)}: {sorted(returned)}"
        assert module_test.request_count > 1, "module did not retry after the 400"
        assert module_test.dropped == 1, f"expected exactly 1 dropped URL, got {module_test.dropped}"


class TestRustywapPrivateFilter(RustywapTestBase):
    """URLs whose host is private/loopback are never submitted to the API."""

    async def setup_after_prep(self, module_test):
        module_test.submitted = []

        def batch_callback(request):
            body = json.loads(request.content)
            module_test.submitted.extend(body["urls"])
            return MockResponse(
                status_code=200,
                json=[{"url": u, "error": None, "technologies": []} for u in body["urls"]],
            )

        module_test.blasthttp_mock.add_callback(batch_callback, url=f"{API_URL}/batch")

        module = module_test.scan.modules["rustywap"]
        private = [
            module_test.scan.make_event(u, "URL", parent=module_test.scan.root_event, tags=["status-200"])
            for u in ("http://10.115.2.50/", "http://127.0.0.1/", "http://192.168.1.10/", "http://172.16.4.4/")
        ]
        public = module_test.scan.make_event(
            f"http://{PUBLIC_HOST}/", "URL", parent=module_test.scan.root_event, tags=["status-200"]
        )
        await module.handle_batch(*private, public)

    def check(self, module_test, events):
        assert module_test.submitted == [f"http://{PUBLIC_HOST}/"], (
            f"only the public URL should have been submitted, got {module_test.submitted}"
        )


class TestRustywapCveCap(RustywapTestBase):
    """CVE FINDINGs are capped at max_cves_per_tech, keeping the highest CVSS scores."""

    config_overrides = {"modules": {"rustywap": {"api_url": API_URL, "max_cves_per_tech": 5}}}

    async def setup_after_prep(self, module_test):
        cves = [
            {"id": "CVE-2024-0001", "score": 2.3, "severity": "LOW", "description": "low", "published": "2024-01-01"},
            {"id": "CVE-2024-0002", "score": 4.7, "severity": "MEDIUM", "description": "m", "published": "2024-01-01"},
            {"id": "CVE-2024-0003", "score": 5.4, "severity": "MEDIUM", "description": "m", "published": "2024-01-01"},
            {"id": "CVE-2024-0004", "score": 6.1, "severity": "MEDIUM", "description": "m", "published": "2024-01-01"},
            {"id": "CVE-2024-0005", "score": 7.5, "severity": "HIGH", "description": "h", "published": "2024-01-01"},
            {"id": "CVE-2024-0006", "score": 8.8, "severity": "HIGH", "description": "h", "published": "2024-01-01"},
            {
                "id": "CVE-2024-0007",
                "score": 9.1,
                "severity": "CRITICAL",
                "description": "c",
                "published": "2024-01-01",
            },
            {
                "id": "CVE-2024-0008",
                "score": 9.8,
                "severity": "CRITICAL",
                "description": "c",
                "published": "2024-01-01",
            },
        ]
        kev = [
            {
                "cve_id": "CVE-2024-0008",
                "vulnerability_name": "bad thing",
                "date_added": "2024-02-01",
                "due_date": "2024-03-01",
                "known_ransomware": True,
                "required_action": "patch",
            }
        ]
        pocs = [
            {
                "cve_id": "CVE-2024-0007",
                "url": "https://github.com/example/poc",
                "name": "poc",
                "stars": 10,
                "pushed_at": "2024-05-01",
                "verified": True,
            }
        ]

        def batch_callback(request):
            body = json.loads(request.content)
            return MockResponse(
                status_code=200,
                json=[
                    {
                        "url": u,
                        "error": None,
                        "technologies": [
                            tech_entry("Apache HTTP Server", version="2.4.37", cves=cves, kev=kev, pocs=pocs)
                        ],
                    }
                    for u in body["urls"]
                ],
            )

        module_test.blasthttp_mock.add_callback(batch_callback, url=f"{API_URL}/batch")

        module = module_test.scan.modules["rustywap"]
        module_test.captured = self.capture_events(module_test)
        _, events = self.make_urls(module_test, 1)
        await module.handle_batch(*events)

    def check(self, module_test, events):
        findings = [d for t, d in module_test.captured if t == "FINDING"]
        cve_findings = [d for d in findings if d.get("cves")]

        assert len(cve_findings) == 5, f"expected 5 CVE FINDINGs, got {len(cve_findings)}"

        emitted = {c for d in cve_findings for c in d["cves"]}
        assert emitted == {
            "CVE-2024-0008",
            "CVE-2024-0007",
            "CVE-2024-0006",
            "CVE-2024-0005",
            "CVE-2024-0004",
        }, f"the cap kept the wrong CVEs: {sorted(emitted)}"
        # the lowest-scoring CVEs are the ones dropped
        assert "CVE-2024-0001" not in emitted
        assert "CVE-2024-0002" not in emitted
        assert "CVE-2024-0003" not in emitted

        by_cve = {d["cves"][0]: d for d in cve_findings}
        assert by_cve["CVE-2024-0008"]["severity"] == "CRITICAL"
        assert by_cve["CVE-2024-0005"]["severity"] == "HIGH"
        assert by_cve["CVE-2024-0004"]["severity"] == "MEDIUM"
        assert "2.4.37" in by_cve["CVE-2024-0008"]["name"]

        assert "CISA KEV" in by_cve["CVE-2024-0008"]["description"]
        assert "CISA KEV" not in by_cve["CVE-2024-0007"]["description"]
        assert "github.com/example/poc" in by_cve["CVE-2024-0007"]["description"]


class TestRustywapApiDown(RustywapTestBase):
    """An unreachable API soft-fails: the module is disabled, the scan continues."""

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(url=f"{API_URL}/health", status_code=503, json={"error": "nope"})

    async def setup_after_prep(self, module_test):
        pass

    def check(self, module_test, events):
        # soft-fail leaves the scan running; the module just isn't in play
        assert module_test.scan.status not in ("FAILED", "ABORTING"), (
            f"a dead API should not abort the scan (status={module_test.scan.status})"
        )


class TestRustywapBisectFullBatch(RustywapTestBase):
    """
    Regression: one bad URL in a FULL batch must cost only that one URL.

    A fixed bisect depth of 4 bottomed out at ~6-URL chunks against a 100-URL batch
    and discarded 6 good results to isolate 1 bad one. The depth is now derived from
    batch_size, so halving can always reach a single URL.
    """

    bad_url = f"http://{PUBLIC_HOST}/page57"

    async def setup_after_prep(self, module_test):
        bad_url = self.bad_url
        module_test.request_count = 0

        def batch_callback(request):
            module_test.request_count += 1
            body = json.loads(request.content)
            if bad_url in body["urls"]:
                return MockResponse(status_code=400, json={"error": f"SSRF check failed for {bad_url}"})
            return MockResponse(
                status_code=200,
                json=[{"url": u, "error": None, "technologies": []} for u in body["urls"]],
            )

        module_test.blasthttp_mock.add_callback(batch_callback, url=f"{API_URL}/batch")

        module = module_test.scan.modules["rustywap"]
        urls, _ = self.make_urls(module_test, 100)
        module_test.results = await module._submit(urls)
        module_test.dropped = module._dropped_urls
        module_test.depth = module.max_bisect_depth

    def check(self, module_test, events):
        # ceil(log2(100)) == 7 halvings to narrow 100 URLs down to 1
        assert module_test.depth == 7, f"expected bisect depth 7 for a 100-URL batch, got {module_test.depth}"

        recovered = {r["url"] for r in module_test.results}
        assert self.bad_url not in recovered, "the rejected URL should not appear in results"
        assert len(recovered) == 99, (
            f"expected all 99 good URLs, recovered {len(recovered)} (dropped {module_test.dropped})"
        )
        assert module_test.dropped == 1, f"only the offending URL should be dropped, got {module_test.dropped}"


class TestRustywapAdvisories(RustywapTestBase):
    """GHSA advisories produce FINDINGs, including ones carrying no CVE."""

    async def setup_after_prep(self, module_test):
        cves = [
            {
                "id": "CVE-2024-1111",
                "score": 9.8,
                "severity": "CRITICAL",
                "description": "already covered by the CVE pass",
                "published": "2024-01-01",
            }
        ]
        advisories = [
            # duplicate of the CVE emitted above — must be suppressed
            {
                "id": "GHSA-dupe-dupe-dupe",
                "cve_id": "CVE-2024-1111",
                "summary": "duplicate",
                "severity": 9.8,
                "severity_level": "CRITICAL",
                "ecosystem": "npm",
                "package_name": "thing",
                "published": "2024-01-01",
            },
            # no CVE at all — would be lost entirely if advisories were ignored
            {
                "id": "GHSA-aaaa-bbbb-cccc",
                "cve_id": None,
                "summary": "prototype pollution in thing",
                "severity": 7.5,
                "severity_level": "HIGH",
                "ecosystem": "npm",
                "package_name": "thing",
                "published": "2024-02-01",
            },
            # GHSA "MODERATE" has no bbot equivalent and must map to MEDIUM
            {
                "id": "GHSA-dddd-eeee-ffff",
                "cve_id": None,
                "summary": "moderate issue",
                "severity": 5.3,
                "severity_level": "MODERATE",
                "ecosystem": "npm",
                "package_name": "thing",
                "published": "2024-03-01",
            },
        ]

        def batch_callback(request):
            body = json.loads(request.content)
            return MockResponse(
                status_code=200,
                json=[
                    {
                        "url": u,
                        "error": None,
                        "technologies": [tech_entry("Thing", version="1.0.0", cves=cves) | {"advisories": advisories}],
                    }
                    for u in body["urls"]
                ],
            )

        module_test.blasthttp_mock.add_callback(batch_callback, url=f"{API_URL}/batch")

        module = module_test.scan.modules["rustywap"]
        module_test.captured = self.capture_events(module_test)
        _, events = self.make_urls(module_test, 1)
        await module.handle_batch(*events)

    def check(self, module_test, events):
        findings = [d for t, d in module_test.captured if t == "FINDING"]
        advisory_findings = [d for d in findings if d["name"].startswith("Vulnerable Package")]

        assert len(advisory_findings) == 2, (
            f"expected 2 advisory FINDINGs (the CVE-duplicated one suppressed), got {len(advisory_findings)}: "
            f"{[d['description'] for d in advisory_findings]}"
        )

        descriptions = " | ".join(d["description"] for d in advisory_findings)
        assert "GHSA-aaaa-bbbb-cccc" in descriptions, "the CVE-less advisory was dropped"
        assert "GHSA-dupe-dupe-dupe" not in descriptions, "advisory duplicating an emitted CVE was not suppressed"
        assert "npm:thing" in descriptions, "ecosystem:package label missing"
        assert "prototype pollution" in descriptions, "advisory summary missing"

        severities = {d["severity"] for d in advisory_findings}
        assert severities == {"HIGH", "MEDIUM"}, f"MODERATE should map to MEDIUM, got {severities}"

        # advisories with no CVE must not populate the FINDING's cves field
        assert all("cves" not in d for d in advisory_findings), "GHSA ids must not be written into the cves field"


class TestRustywapPerHostOnly(RustywapTestBase):
    """
    Regression: a host must be analyzed once, not once per scheme/port.

    per_hostport_only treated http://host:80 and https://host:443 as two services, so a
    host whose port 80 redirects to 443 produced two identical sets of TECHNOLOGY events
    and cost two API calls.
    """

    async def setup_after_prep(self, module_test):
        pass

    def check(self, module_test, events):
        module = module_test.scan.modules["rustywap"]
        assert module.per_host_only is True, "module must dedupe incoming URLs per host"
        assert module.per_hostport_only is False, "per_hostport_only would re-analyze the same host on both 80 and 443"
        # the dedup hash BaseModule actually uses must be the per-host one
        event = module_test.scan.make_event(
            f"https://{PUBLIC_HOST}/", "URL", parent=module_test.scan.root_event, tags=["status-200"]
        )
        _, reason = module._incoming_dedup_hash(event)
        assert reason == "per_host_only=True", f"unexpected dedup strategy: {reason}"
