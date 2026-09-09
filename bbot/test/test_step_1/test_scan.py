from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_scan(
    events,
    helpers,
    monkeypatch,
    bbot_scanner,
):
    scan0 = bbot_scanner(
        "1.1.1.0",
        "1.1.1.1/31",
        "evilcorp.com",
        "test.evilcorp.com",
        blacklist=["1.1.1.1/28", "www.evilcorp.com"],
        modules=["ipneighbor"],
    )
    await scan0._prep()
    assert scan0.in_target("1.1.1.1")
    assert scan0.in_target("1.1.1.0")
    assert scan0.blacklisted("1.1.1.15")
    assert not scan0.blacklisted("1.1.1.16")
    assert scan0.blacklisted("1.1.1.1/30")
    assert not scan0.blacklisted("1.1.1.1/27")
    assert not scan0.in_scope("1.1.1.1")
    assert scan0.in_target("api.evilcorp.com")
    assert scan0.in_target("www.evilcorp.com")
    assert not scan0.blacklisted("api.evilcorp.com")
    assert scan0.blacklisted("asdf.www.evilcorp.com")
    assert scan0.in_scope("test.api.evilcorp.com")
    assert not scan0.in_scope("test.www.evilcorp.com")
    assert not scan0.in_scope("www.evilcorp.co.uk")
    j = scan0.json
    assert not "seeds" in j["target"], "seeds should not be in target json"
    # Positional arguments become the target
    assert set(j["target"]["target"]) == {"1.1.1.0", "1.1.1.0/31", "evilcorp.com", "test.evilcorp.com"}
    # Seeds are backfilled from target when not explicitly set
    assert scan0.target.target.hosts == {"1.1.1.0/31", "evilcorp.com"}
    assert set(j["target"]["blacklist"]) == {"1.1.1.0/28", "www.evilcorp.com"}
    assert "ipneighbor" in j["preset"]["modules"]

    scan1 = bbot_scanner("1.0.0.1", seeds=["1.1.1.1"])
    assert not scan1.blacklisted("1.1.1.1")
    assert not scan1.blacklisted("1.0.0.1")
    assert not scan1.in_target("1.1.1.1")
    assert scan1.in_target("1.0.0.1")
    assert scan1.in_scope("1.0.0.1")
    assert not scan1.in_scope("1.1.1.1")

    scan2 = bbot_scanner("1.1.1.1")
    await scan2._prep()
    assert not scan2.blacklisted("1.1.1.1")
    assert not scan2.blacklisted("1.0.0.1")
    assert scan2.in_target("1.1.1.1")
    assert not scan2.in_target("1.0.0.1")
    assert scan2.in_scope("1.1.1.1")
    assert not scan2.in_scope("1.0.0.1")

    dns_table = {
        "1.1.1.1.in-addr.arpa": {"PTR": ["one.one.one.one"]},
        "one.one.one.one": {"A": ["1.1.1.1"]},
    }

    # make sure DNS resolution works
    scan4 = bbot_scanner("1.1.1.1", config={"dns": {"minimal": False}})
    await scan4._prep()
    await scan4.helpers.dns._mock_dns(dns_table)
    events = []
    async for event in scan4.async_start():
        events.append(event)
    event_data = [e.pretty_string for e in events]
    assert "one.one.one.one" in event_data

    # make sure it doesn't work when you turn it off
    scan5 = bbot_scanner("1.1.1.1", config={"dns": {"minimal": True}})
    await scan5._prep()
    await scan5.helpers.dns._mock_dns(dns_table)
    events = []
    async for event in scan5.async_start():
        events.append(event)
    event_data = [e.pretty_string for e in events]
    assert "one.one.one.one" not in event_data

    for scan in (scan0, scan1, scan2, scan4, scan5):
        await scan._cleanup()

    scan6 = bbot_scanner("a.foobar.io", "b.foobar.io", "c.foobar.io", "foobar.io")
    await scan6._prep()
    assert len(scan6.dns_strings) == 1


def test_seeds_target_separation(bbot_scanner):
    """
    Test that when seeds are explicitly provided (via -s), they are properly separated from target.
    """
    # Simulate: bbot -t 192.168.1.0/24 -s seed1.example.com seed2.example.com
    scan = bbot_scanner(
        "192.168.1.0/24",
        seeds=["seed1.example.com", "seed2.example.com"],
    )

    # Verify target and seeds are properly separated in JSON
    j = scan.json
    assert set(j["target"]["target"]) == {"192.168.1.0/24"}, "Target should only contain the IP range"
    assert set(j["target"]["seeds"]) == {"seed1.example.com", "seed2.example.com"}, (
        "Seeds should contain the DNS names, not the target"
    )

    # Verify target functionality
    assert scan.in_target("192.168.1.1"), "IP in target range should be in target"
    assert not scan.in_target("seed1.example.com"), "Seed DNS name should not be in target"
    assert not scan.in_target("seed2.example.com"), "Seed DNS name should not be in target"

    # Verify seeds are accessible
    assert "seed1.example.com" in scan.target.seeds.inputs, "seed1.example.com should be in seeds"
    assert "seed2.example.com" in scan.target.seeds.inputs, "seed2.example.com should be in seeds"
    assert "192.168.1.0/24" not in scan.target.seeds.inputs, (
        "Target should not be in seeds when seeds are explicitly provided"
    )


@pytest.mark.asyncio
async def test_task_scan_handle_event_timeout(bbot_scanner):
    from bbot.modules.base import BaseModule

    # make a module that takes a long time to handle an event
    class LongModule(BaseModule):
        watched_events = ["IP_ADDRESS"]
        handled_event = False
        cancelled = False
        _name = "long"

        async def handle_event(self, event):
            self.handled_event = True
            try:
                await self.helpers.sleep(99999999)
            except asyncio.CancelledError:
                self.cancelled = True
                raise

    # same thing but handle_batch
    class LongBatchModule(BaseModule):
        watched_events = ["IP_ADDRESS"]
        handled_event = False
        _name = "long_batch"
        _batch_size = 2

        async def handle_batch(self, *events):
            self.handled_event = True
            try:
                await self.helpers.sleep(99999999)
            except asyncio.CancelledError:
                self.cancelled = True
                raise

    # scan with both modules
    scan = bbot_scanner(
        "127.0.0.1",
        config={
            "module_handle_event_timeout": 5,
            "module_handle_batch_timeout": 5,
        },
    )
    await scan._prep()
    scan.modules["long"] = LongModule(scan=scan)
    scan.modules["long_batch"] = LongBatchModule(scan=scan)
    events = [e async for e in scan.async_start()]
    assert events
    assert any(e.data == "127.0.0.1" for e in events)
    # make sure both modules were called
    assert scan.modules["long"].handled_event
    assert scan.modules["long_batch"].handled_event
    # they should also be cancelled
    assert scan.modules["long"].cancelled
    assert scan.modules["long_batch"].cancelled


@pytest.mark.asyncio
async def test_url_extension_handling(bbot_scanner):
    scan = bbot_scanner(config={"url_extension_blacklist": ["css"]})
    await scan._prep()
    assert scan.url_extension_blacklist == {"css"}
    good_event = scan.make_event("https://evilcorp.com/a.txt", "URL", tags=["status-200"], parent=scan.root_event)
    bad_event = scan.make_event("https://evilcorp.com/a.css", "URL", tags=["status-200"], parent=scan.root_event)
    assert "blacklisted" not in bad_event.tags
    result = await scan.ingress_module.handle_event(good_event)
    assert result is None
    result, reason = await scan.ingress_module.handle_event(bad_event)
    assert result is False
    assert reason == "event is blacklisted"
    assert "blacklisted" in bad_event.tags

    await scan._cleanup()


@pytest.mark.asyncio
async def test_speed_counter():
    from bbot.scanner.stats import SpeedCounter

    # counter with 1-second window
    counter = SpeedCounter(1)
    # 10 events spread across 2 seconds
    for i in range(10):
        counter.tick()
        await asyncio.sleep(0.2)
    # only 5 should show
    assert 4 <= counter.speed <= 5


@pytest.mark.asyncio
async def test_stats_attribution():
    from bbot.scanner.stats import ScanStats
    from types import SimpleNamespace

    def mock_module(name, produced_events=None):
        return SimpleNamespace(name=name, _stats_exclude=False, produced_events=produced_events or [])

    def mock_event(type, module, parent=None):
        e = SimpleNamespace(type=type, module=module)
        if parent is not None:
            e.parent = parent
        return e

    mock_scan = SimpleNamespace(status_frequency=60)
    stats = ScanStats(mock_scan)

    http_mod = mock_module("http", ["URL", "HTTP_RESPONSE"])
    excavate_mod = mock_module("excavate", ["URL_UNVERIFIED", "WEB_PARAMETER"])
    webbrute_shortnames_mod = mock_module("webbrute_shortnames", ["URL_UNVERIFIED"])
    webbrute_mod = mock_module("webbrute", ["URL_UNVERIFIED"])
    speculate_mod = mock_module("speculate", ["DNS_NAME", "OPEN_TCP_PORT", "IP_ADDRESS", "FINDING", "ORG_STUB"])
    robots_mod = mock_module("robots", ["URL_UNVERIFIED"])

    # 1) excavate discovers URL_UNVERIFIED from HTTP_RESPONSE, http verifies → excavate gets credit
    for _ in range(5):
        parent = mock_event("URL_UNVERIFIED", excavate_mod)
        stats.event_produced(mock_event("URL", http_mod, parent=parent))

    # 2) webbrute_shortnames discovers URL_UNVERIFIED, http verifies → webbrute_shortnames gets credit
    for _ in range(3):
        parent = mock_event("URL_UNVERIFIED", webbrute_shortnames_mod)
        stats.event_produced(mock_event("URL", http_mod, parent=parent))

    # 3) webbrute discovers URL_UNVERIFIED, http verifies → webbrute gets credit
    parent = mock_event("URL_UNVERIFIED", webbrute_mod)
    stats.event_produced(mock_event("URL", http_mod, parent=parent))

    # 4) speculate (internal module) creates URL_UNVERIFIED, http verifies → http keeps credit
    for _ in range(4):
        parent = mock_event("URL_UNVERIFIED", speculate_mod)
        stats.event_produced(mock_event("URL", http_mod, parent=parent))

    # 5) robots discovers URL_UNVERIFIED, http verifies → robots gets credit
    for _ in range(2):
        parent = mock_event("URL_UNVERIFIED", robots_mod)
        stats.event_produced(mock_event("URL", http_mod, parent=parent))

    # 6) http discovers URL directly from OPEN_TCP_PORT (no URL_UNVERIFIED parent) → http keeps credit
    for _ in range(2):
        parent = mock_event("OPEN_TCP_PORT", mock_module("portscan"))
        stats.event_produced(mock_event("URL", http_mod, parent=parent))

    # 7) non-URL event types are unaffected
    stats.event_produced(mock_event("DNS_NAME", mock_module("CNAME")))
    stats.event_produced(mock_event("STORAGE_BUCKET", mock_module("cloudcheck")))

    # verify per-module produced counts
    assert stats.module_stats["excavate"].produced == {"URL": 5}
    assert stats.module_stats["webbrute_shortnames"].produced == {"URL": 3}
    assert stats.module_stats["webbrute"].produced == {"URL": 1}
    assert stats.module_stats["robots"].produced == {"URL": 2}
    # http gets credit for speculate's 4 URLs + 2 from OPEN_TCP_PORT = 6
    assert stats.module_stats["http"].produced == {"URL": 6}
    assert "speculate" not in stats.module_stats
    assert stats.module_stats["CNAME"].produced == {"DNS_NAME": 1}
    assert stats.module_stats["cloudcheck"].produced == {"STORAGE_BUCKET": 1}

    # verify the table output (sorted by produced_total descending)
    table = stats.table()
    header = table[0]
    rows = table[1:]
    assert header == ["Module", "Produced", "Consumed"]

    # build a dict of module_name -> produced_str from the table
    table_dict = {row[0]: row[1] for row in rows}
    assert table_dict["http"] == "6 (6 URL)"
    assert table_dict["excavate"] == "5 (5 URL)"
    assert table_dict["webbrute_shortnames"] == "3 (3 URL)"
    assert table_dict["robots"] == "2 (2 URL)"
    assert table_dict["webbrute"] == "1 (1 URL)"
    assert table_dict["CNAME"] == "1 (1 DNS_NAME)"
    assert table_dict["cloudcheck"] == "1 (1 STORAGE_BUCKET)"
    assert "speculate" not in table_dict

    # verify sort order (highest produced first)
    produced_totals = [stats.module_stats[row[0]].produced_total for row in rows]
    assert produced_totals == sorted(produced_totals, reverse=True)


@pytest.mark.asyncio
async def test_python_output_matches_json(bbot_scanner):
    import json

    scan = bbot_scanner(
        "blacklanternsecurity.com",
        config={"speculate": True, "dns": {"minimal": False}, "scope": {"report_distance": 10}},
    )
    await scan._prep()
    await scan.helpers.dns._mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.1"]}})
    events = [e.json() async for e in scan.async_start()]
    output_json = scan.home / "output.json"
    json_events = []
    for line in open(output_json):
        json_events.append(json.loads(line))

    assert len(events) == 5
    scan_events = [e for e in events if e["type"] == "SCAN"]
    assert len(scan_events) == 2
    assert all(isinstance(e["data_json"]["status"], str) for e in scan_events)
    assert len([e for e in events if e["type"] == "DNS_NAME"]) == 1
    assert len([e for e in events if e["type"] == "ORG_STUB"]) == 1
    assert len([e for e in events if e["type"] == "IP_ADDRESS"]) == 1
    assert events == json_events


@pytest.mark.asyncio
async def test_huge_target_list(bbot_scanner, monkeypatch):
    # single target should only have one rule
    scan = bbot_scanner("evilcorp.com", config={"excavate": True})
    await scan._prep()
    assert "hostname_extraction_0" in scan.modules["excavate"].yara_rules_dict
    assert "hostname_extraction_1" not in scan.modules["excavate"].yara_rules_dict

    # over 10000 targets should be broken into two rules
    num_targets = 10005
    targets = [f"evil{i}.com" for i in range(num_targets)]
    scan = bbot_scanner(*targets, config={"excavate": True})
    await scan._prep()
    assert "hostname_extraction_0" in scan.modules["excavate"].yara_rules_dict
    assert "hostname_extraction_1" in scan.modules["excavate"].yara_rules_dict
    assert "hostname_extraction_2" not in scan.modules["excavate"].yara_rules_dict


@pytest.mark.asyncio
async def test_exclude_cdn(bbot_scanner, monkeypatch, clean_default_config):
    # test that CDN exclusion works

    from bbot.scanner import Preset

    dns_mock = {
        "evilcorp.com": {"A": ["127.0.0.1"]},
        "www.evilcorp.com": {"A": ["127.0.0.1"]},
    }

    # first, run a scan with no CDN exclusion
    scan = bbot_scanner("evilcorp.com")
    await scan._prep()
    await scan.helpers._mock_dns(dns_mock)

    from bbot.modules.base import BaseModule

    class DummyModule(BaseModule):
        watched_events = ["DNS_NAME"]

        async def handle_event(self, event):
            if event.type == "DNS_NAME" and event.data == "evilcorp.com":
                await self.emit_event("www.evilcorp.com", "DNS_NAME", parent=event, tags=["cloudflare", "cdn"])
            if event.type == "DNS_NAME" and event.data == "www.evilcorp.com":
                await self.emit_event("www.evilcorp.com:80", "OPEN_TCP_PORT", parent=event, tags=["cloudflare", "cdn"])
                await self.emit_event(
                    "www.evilcorp.com:443", "OPEN_TCP_PORT", parent=event, tags=["cloudflare", "cdn"]
                )
                await self.emit_event(
                    "www.evilcorp.com:8080", "OPEN_TCP_PORT", parent=event, tags=["cloudflare", "cdn"]
                )

    dummy = DummyModule(scan=scan)
    scan.modules["dummy"] = dummy
    events = [e async for e in scan.async_start() if e.type in ("DNS_NAME", "OPEN_TCP_PORT")]
    assert set(e.data for e in events) == {
        "evilcorp.com",
        "www.evilcorp.com",
        "www.evilcorp.com:80",
        "www.evilcorp.com:443",
        "www.evilcorp.com:8080",
    }

    monkeypatch.setattr("sys.argv", ["bbot", "-t", "evilcorp.com", "--exclude-cdn"])

    # then run a scan with --exclude-cdn enabled
    preset = Preset("evilcorp.com")
    preset.parse_args()
    baked_preset = preset.validate().bake()
    assert baked_preset.to_yaml() == "modules:\n- portfilter\n"
    scan = bbot_scanner("evilcorp.com", preset=preset)
    await scan._prep()
    await scan.helpers._mock_dns(dns_mock)
    dummy = DummyModule(scan=scan)
    scan.modules["dummy"] = dummy
    events = [e async for e in scan.async_start() if e.type in ("DNS_NAME", "OPEN_TCP_PORT")]
    assert set(e.data for e in events) == {
        "evilcorp.com",
        "www.evilcorp.com",
        "www.evilcorp.com:80",
        "www.evilcorp.com:443",
    }


@pytest.mark.asyncio
async def test_scan_event_started_at_type(bbot_scanner):
    """Regression test: started_at must be a float on both RUNNING and FINISHED SCAN events."""
    scan = bbot_scanner("127.0.0.1")
    await scan._prep()
    scan_events = []
    async for event in scan.async_start():
        if event.type == "SCAN":
            scan_events.append(event)

    assert len(scan_events) == 2, f"Expected 2 SCAN events, got {len(scan_events)}"
    for e in scan_events:
        started_at = e.data.get("started_at")
        status = e.data.get("status")
        assert isinstance(started_at, float), (
            f"SCAN event (status={status}) started_at should be float, got {type(started_at).__name__}: {started_at!r}"
        )


async def test_scan_name(bbot_scanner):
    scan = bbot_scanner("evilcorp.com", name="test_scan_name")
    await scan._prep()
    assert scan.name == "test_scan_name"
    assert scan.preset.scan_name == "test_scan_name"


@pytest.mark.asyncio
async def test_memory_backpressure_throttle(bbot_scanner, monkeypatch):
    """Ingress delay scales linearly with memory overshoot, and the scan still completes under pressure."""
    from types import SimpleNamespace

    mem_percent = [50.0]

    def mock_memory_status():
        return SimpleNamespace(percent=mem_percent[0], available=1_000_000_000)

    scan = bbot_scanner("127.0.0.1", config={"max_mem_percent": 90})
    await scan._prep()
    await scan.helpers.dns._mock_dns({"1.1.1.1.in-addr.arpa": {"PTR": ["one.one.one.one"]}})
    monkeypatch.setattr("bbot.core.helpers.misc.memory_status", mock_memory_status)

    # delay curve — pure function of memory percent
    assert scan._compute_ingress_delay(50.0) == 0.0
    assert scan._compute_ingress_delay(90.0) == 0.0
    assert scan._compute_ingress_delay(91.0) == pytest.approx(1.0)
    assert scan._compute_ingress_delay(92.5) == pytest.approx(2.5)
    assert scan._compute_ingress_delay(95.0) == pytest.approx(5.0)
    # capped above threshold+5
    assert scan._compute_ingress_delay(99.0) == pytest.approx(5.0)

    # status loop wires memory_status -> _ingress_delay
    assert scan._ingress_delay == 0.0

    # the drain-mode bypass only zeros the delay when no module has work; pin a fake task so
    # the engagement curve below exercises the memory-driven formula, not the bypass
    target_module = next(m for m in scan.modules.values() if not m._intercept)
    target_module._task_counter.tasks["fake-task"] = SimpleNamespace(n=1)
    try:
        mem_percent[0] = 93.0
        scan.modules_status(_log=False)
        assert scan._ingress_delay == pytest.approx(3.0), "delay should engage above threshold"

        mem_percent[0] = 97.0
        scan.modules_status(_log=False)
        assert scan._ingress_delay == pytest.approx(5.0), "delay should clamp at the cap"

        mem_percent[0] = 80.0
        scan.modules_status(_log=False)
        assert scan._ingress_delay == 0.0, "delay should clear once memory drops back"
    finally:
        target_module._task_counter.tasks.pop("fake-task", None)

    # scan still produces events with the throttle disengaged
    events = [e async for e in scan.async_start()]
    assert any(e.type == "IP_ADDRESS" for e in events), "scan should still produce events"


@pytest.mark.asyncio
async def test_memory_backpressure_drain_mode_bypass(bbot_scanner, monkeypatch):
    """Throttle must clear in drain mode: with memory pinned high but no module producing,
    ingress IS the drain and throttling it traps the scan in a feedback loop."""
    from types import SimpleNamespace

    mem_percent = [93.0]

    def mock_memory_status():
        return SimpleNamespace(percent=mem_percent[0], available=1_000_000_000)

    scan = bbot_scanner("127.0.0.1", config={"max_mem_percent": 90})
    await scan._prep()
    monkeypatch.setattr("bbot.core.helpers.misc.memory_status", mock_memory_status)

    non_intercept = [m for m in scan.modules.values() if not m._intercept]
    assert non_intercept, "test requires at least one non-intercept module"

    # simulate a healthy scan: at least one module is mid-handle
    target_module = non_intercept[0]
    target_module._task_counter.tasks["fake-task"] = SimpleNamespace(n=1)
    try:
        scan.modules_status(_log=False)
        assert scan._ingress_delay == pytest.approx(3.0), (
            "throttle should engage when memory is high and a module is running"
        )
    finally:
        target_module._task_counter.tasks.pop("fake-task", None)

    # now drain mode: no module running, no module has queued work
    for m in non_intercept:
        assert not m.running
        assert m.outgoing_event_queue.qsize() == 0
        assert m.num_incoming_events == 0
    scan.modules_status(_log=False)
    assert scan._ingress_delay == 0.0, "throttle must clear in drain mode (no producers, ingress is the drain)"
