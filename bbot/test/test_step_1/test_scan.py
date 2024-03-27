from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_scan(
    events,
    bbot_config,
    helpers,
    monkeypatch,
    bbot_scanner,
    mock_dns,
):
    scan0 = bbot_scanner(
        "1.1.1.1/31",
        "evilcorp.com",
        blacklist=["1.1.1.1/28", "www.evilcorp.com"],
        modules=["ipneighbor"],
        config=bbot_config,
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
    assert "1.1.1.0/31" in j["targets"]
    assert "1.1.1.0/31" in j["whitelist"]
    assert "1.1.1.0/28" in j["blacklist"]
    assert "ipneighbor" in j["modules"]

    scan1 = bbot_scanner("1.1.1.1", whitelist=["1.0.0.1"], config=bbot_config)
    assert not scan1.blacklisted("1.1.1.1")
    assert not scan1.blacklisted("1.0.0.1")
    assert not scan1.whitelisted("1.1.1.1")
    assert scan1.whitelisted("1.0.0.1")
    assert scan1.in_scope("1.0.0.1")
    assert not scan1.in_scope("1.1.1.1")

    scan2 = bbot_scanner("1.1.1.1", config=bbot_config)
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
    dns_config = OmegaConf.create({"dns_resolution": True})
    dns_config = OmegaConf.merge(bbot_config, dns_config)
    scan4 = bbot_scanner("1.1.1.1", config=dns_config)
    mock_dns(scan4, dns_table)
    events = []
    async for event in scan4.async_start():
        events.append(event)
    event_data = [e.data for e in events]
    assert "one.one.one.one" in event_data

    # make sure it doesn't work when you turn it off
    no_dns_config = OmegaConf.create({"dns_resolution": False})
    no_dns_config = OmegaConf.merge(bbot_config, no_dns_config)
    scan5 = bbot_scanner("1.1.1.1", config=no_dns_config)
    mock_dns(scan5, dns_table)
    events = []
    async for event in scan5.async_start():
        events.append(event)
    event_data = [e.data for e in events]
    assert "one.one.one.one" not in event_data
