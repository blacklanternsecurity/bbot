from ..bbot_fixtures import *


def test_scan(
    patch_ansible,
    patch_commands,
    events,
    bbot_config,
    helpers,
    neograph,
    websocketapp,
    monkeypatch,
    bbot_scanner,
):
    scan0 = bbot_scanner(
        "8.8.8.8/31", "evilcorp.com", blacklist=["8.8.8.8/28", "www.evilcorp.com"], config=bbot_config
    )
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

    scan3 = bbot_scanner(
        "127.0.0.0/30",
        "127.0.0.2:8443",
        "https://localhost",
        "[::1]:80",
        "http://[::1]:8080",
        modules=["ipneighbor"],
        output_modules=list(available_output_modules),
        config=bbot_config,
        blacklist=["http://127.0.0.3:8000/asdf"],
        whitelist=["127.0.0.0/29"],
    )
    patch_commands(scan3)
    patch_ansible(scan3)
    assert "targets" in scan3.json
    assert "127.0.0.3" in scan3.target
    assert "127.0.0.4" not in scan3.target
    assert "127.0.0.4" in scan3.whitelist
    assert scan3.whitelisted("127.0.0.4")
    assert "127.0.0.3" in scan3.blacklist
    assert scan3.blacklisted("127.0.0.3")
    assert scan3.in_scope("127.0.0.1")
    assert not scan3.in_scope("127.0.0.3")
    scan3.prep()
    monkeypatch.setattr(scan3.modules["websocket"], "ws", websocketapp())
    events = list(scan3.start())

    # make sure DNS resolution works
    dns_config = OmegaConf.create({"dns_resolution": True})
    dns_config = OmegaConf.merge(bbot_config, dns_config)
    scan4 = bbot_scanner("8.8.8.8", config=dns_config)
    events = list(scan4.start())
    event_data = [e.data for e in events]
    assert "dns.google" in event_data

    # make sure it doesn't work when you turn it off
    no_dns_config = OmegaConf.create({"dns_resolution": False})
    no_dns_config = OmegaConf.merge(bbot_config, no_dns_config)
    scan5 = bbot_scanner("8.8.8.8", config=no_dns_config)
    events = list(scan5.start())
    event_data = [e.data for e in events]
    assert "dns.google" not in event_data
