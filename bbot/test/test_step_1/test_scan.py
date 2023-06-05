from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_scan(
    events,
    bbot_config,
    helpers,
    neograph,
    monkeypatch,
    bbot_scanner,
):
    scan0 = bbot_scanner(
        "8.8.8.8/31",
        "evilcorp.com",
        blacklist=["8.8.8.8/28", "www.evilcorp.com"],
        modules=["ipneighbor"],
        config=bbot_config,
    )
    await scan0.load_modules()
    assert scan0.whitelisted("8.8.8.8")
    assert scan0.whitelisted("8.8.8.9")
    assert scan0.blacklisted("8.8.8.15")
    assert not scan0.blacklisted("8.8.8.16")
    assert scan0.blacklisted("8.8.8.8/30")
    assert not scan0.blacklisted("8.8.8.8/27")
    assert not scan0.in_scope("8.8.8.8")
    assert scan0.whitelisted("api.evilcorp.com")
    assert scan0.whitelisted("www.evilcorp.com")
    assert not scan0.blacklisted("api.evilcorp.com")
    assert scan0.blacklisted("asdf.www.evilcorp.com")
    assert scan0.in_scope("test.api.evilcorp.com")
    assert not scan0.in_scope("test.www.evilcorp.com")
    assert not scan0.in_scope("www.evilcorp.co.uk")
    j = scan0.json
    assert "8.8.8.8/31" in j["targets"]
    assert "8.8.8.8/31" in j["whitelist"]
    assert "8.8.8.0/28" in j["blacklist"]
    assert "ipneighbor" in j["modules"]

    scan1 = bbot_scanner("8.8.8.8", whitelist=["8.8.4.4"], config=bbot_config)
    assert not scan1.blacklisted("8.8.8.8")
    assert not scan1.blacklisted("8.8.4.4")
    assert not scan1.whitelisted("8.8.8.8")
    assert scan1.whitelisted("8.8.4.4")
    assert scan1.in_scope("8.8.4.4")
    assert not scan1.in_scope("8.8.8.8")

    scan2 = bbot_scanner("8.8.8.8", config=bbot_config)
    assert not scan2.blacklisted("8.8.8.8")
    assert not scan2.blacklisted("8.8.4.4")
    assert scan2.whitelisted("8.8.8.8")
    assert not scan2.whitelisted("8.8.4.4")
    assert scan2.in_scope("8.8.8.8")
    assert not scan2.in_scope("8.8.4.4")

    # make sure DNS resolution works
    dns_config = OmegaConf.create({"dns_resolution": True})
    dns_config = OmegaConf.merge(bbot_config, dns_config)
    scan4 = bbot_scanner("8.8.8.8", config=dns_config)
    events = []
    async for event in scan4.async_start():
        events.append(event)
    event_data = [e.data for e in events]
    assert "dns.google" in event_data

    # make sure it doesn't work when you turn it off
    no_dns_config = OmegaConf.create({"dns_resolution": False})
    no_dns_config = OmegaConf.merge(bbot_config, no_dns_config)
    scan5 = bbot_scanner("8.8.8.8", config=no_dns_config)
    events = []
    async for event in scan5.async_start():
        events.append(event)
    event_data = [e.data for e in events]
    assert "dns.google" not in event_data
