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
        blacklist=["1.1.1.1/28", "www.evilcorp.com"],
        modules=["ipneighbor"],
    )
    await scan0.load_modules()
    assert scan0.whitelisted("1.1.1.1")
    assert scan0.whitelisted("1.1.1.0")
    assert scan0.blacklisted("1.1.1.15")
    assert not scan0.blacklisted("1.1.1.16")
    assert scan0.blacklisted("1.1.1.1/30")
    assert not scan0.blacklisted("1.1.1.1/27")
    assert not scan0.in_scope("1.1.1.1")
    assert scan0.whitelisted("api.evilcorp.com")
    assert scan0.whitelisted("www.evilcorp.com")
    assert not scan0.blacklisted("api.evilcorp.com")
    assert scan0.blacklisted("asdf.www.evilcorp.com")
    assert scan0.in_scope("test.api.evilcorp.com")
    assert not scan0.in_scope("test.www.evilcorp.com")
    assert not scan0.in_scope("www.evilcorp.co.uk")
    j = scan0.json
    assert set(j["target"]["seeds"]) == {"1.1.1.0", "1.1.1.0/31", "evilcorp.com"}
    assert set(j["target"]["whitelist"]) == {"1.1.1.0/31", "evilcorp.com"}
    assert set(j["target"]["blacklist"]) == {"1.1.1.0/28", "www.evilcorp.com"}
    assert "ipneighbor" in j["preset"]["modules"]

    scan1 = bbot_scanner("1.1.1.1", whitelist=["1.0.0.1"])
    assert not scan1.blacklisted("1.1.1.1")
    assert not scan1.blacklisted("1.0.0.1")
    assert not scan1.whitelisted("1.1.1.1")
    assert scan1.whitelisted("1.0.0.1")
    assert scan1.in_scope("1.0.0.1")
    assert not scan1.in_scope("1.1.1.1")

    scan2 = bbot_scanner("1.1.1.1")
    assert not scan2.blacklisted("1.1.1.1")
    assert not scan2.blacklisted("1.0.0.1")
    assert scan2.whitelisted("1.1.1.1")
    assert not scan2.whitelisted("1.0.0.1")
    assert scan2.in_scope("1.1.1.1")
    assert not scan2.in_scope("1.0.0.1")

    dns_table = {
        "1.1.1.1.in-addr.arpa": {"PTR": ["one.one.one.one"]},
        "one.one.one.one": {"A": ["1.1.1.1"]},
    }

    # make sure DNS resolution works
    scan4 = bbot_scanner("1.1.1.1", config={"dns": {"minimal": False}})
    await scan4.helpers.dns._mock_dns(dns_table)
    events = []
    async for event in scan4.async_start():
        events.append(event)
    event_data = [e.data for e in events]
    assert "one.one.one.one" in event_data

    # make sure it doesn't work when you turn it off
    scan5 = bbot_scanner("1.1.1.1", config={"dns": {"minimal": True}})
    await scan5.helpers.dns._mock_dns(dns_table)
    events = []
    async for event in scan5.async_start():
        events.append(event)
    event_data = [e.data for e in events]
    assert "one.one.one.one" not in event_data

    for scan in (scan0, scan1, scan2, scan4, scan5):
        await scan._cleanup()

    scan6 = bbot_scanner("a.foobar.io", "b.foobar.io", "c.foobar.io", "foobar.io")
    assert len(scan6.dns_strings) == 1


@pytest.mark.asyncio
async def test_url_extension_handling(bbot_scanner):
    scan = bbot_scanner(config={"url_extension_blacklist": ["css"], "url_extension_httpx_only": ["js"]})
    await scan._prep()
    assert scan.url_extension_blacklist == {"css"}
    assert scan.url_extension_httpx_only == {"js"}
    good_event = scan.make_event("https://evilcorp.com/a.txt", "URL", tags=["status-200"], parent=scan.root_event)
    bad_event = scan.make_event("https://evilcorp.com/a.css", "URL", tags=["status-200"], parent=scan.root_event)
    httpx_event = scan.make_event("https://evilcorp.com/a.js", "URL", tags=["status-200"], parent=scan.root_event)
    assert "blacklisted" not in bad_event.tags
    assert "httpx-only" not in httpx_event.tags
    result = await scan.ingress_module.handle_event(good_event)
    assert result == None
    result, reason = await scan.ingress_module.handle_event(bad_event)
    assert result == False
    assert reason == "event is blacklisted"
    assert "blacklisted" in bad_event.tags
    result = await scan.ingress_module.handle_event(httpx_event)
    assert result == None
    assert "httpx-only" in httpx_event.tags

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
async def test_python_output_matches_json(bbot_scanner):
    import json

    scan = bbot_scanner(
        "blacklanternsecurity.com",
        config={"speculate": True, "dns": {"minimal": False}, "scope": {"report_distance": 10}},
    )
    await scan.helpers.dns._mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.1"]}})
    events = [e.json() async for e in scan.async_start()]
    output_json = scan.home / "output.json"
    json_events = []
    for line in open(output_json):
        json_events.append(json.loads(line))

    assert len(events) == 5
    scan_events = [e for e in events if e["type"] == "SCAN"]
    assert len(scan_events) == 2
    assert all([isinstance(e["data"]["status"], str) for e in scan_events])
    assert len([e for e in events if e["type"] == "DNS_NAME"]) == 1
    assert len([e for e in events if e["type"] == "ORG_STUB"]) == 1
    assert len([e for e in events if e["type"] == "IP_ADDRESS"]) == 1
    assert events == json_events
