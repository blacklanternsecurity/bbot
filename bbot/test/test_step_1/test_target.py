from ..bbot_fixtures import *  # noqa: F401


def test_target(bbot_config, bbot_scanner):
    scan1 = bbot_scanner("api.publicapis.org", "8.8.8.8/30", "2001:4860:4860::8888/126", config=bbot_config)
    scan2 = bbot_scanner("8.8.8.8/29", "publicapis.org", "2001:4860:4860::8888/125", config=bbot_config)
    scan3 = bbot_scanner("8.8.8.8/29", "publicapis.org", "2001:4860:4860::8888/125", config=bbot_config)
    scan4 = bbot_scanner("8.8.8.8/29", config=bbot_config)
    scan5 = bbot_scanner(config=bbot_config)
    assert not scan5.target
    assert len(scan1.target) == 9
    assert len(scan4.target) == 8
    assert_target_presence("8.8.8.9", scan1, "8.8.8.12", "8.8.8.8/31")
    assert_target_presence(
        "8.8.8.8/30", scan1, "8.8.8.8/29", "2001:4860:4860::8889"
    )
    assert "2001:4860:4860::888c" not in scan1.target
    assert "www.api.publicapis.org" in scan1.target
    assert_target_presence(
        "api.publicapis.org",
        scan1,
        "publicapis.org",
        "bob@www.api.publicapis.org",
    )
    assert "https://www.api.publicapis.org" in scan1.target
    assert "www.api.publicapis.org:80" in scan1.target
    assert scan1.make_event("https://[2001:4860:4860::8888]:80", dummy=True) in scan1.target
    assert scan1.make_event("[2001:4860:4860::8888]:80", "OPEN_TCP_PORT", dummy=True) in scan1.target
    assert scan1.make_event("[2001:4860:4860::888c]:80", "OPEN_TCP_PORT", dummy=True) not in scan1.target
    assert scan1.target in scan2.target
    assert scan2.target not in scan1.target
    assert scan3.target in scan2.target
    assert scan2.target == scan3.target
    assert scan4.target != scan1.target

    assert str(scan1.target.get("8.8.8.9").host) == "8.8.8.8/30"
    assert scan1.target.get("8.8.8.12") is None
    assert str(scan1.target.get("2001:4860:4860::8889").host) == "2001:4860:4860::8888/126"
    assert scan1.target.get("2001:4860:4860::888c") is None
    assert str(scan1.target.get("www.api.publicapis.org").host) == "api.publicapis.org"
    assert scan1.target.get("publicapis.org") is None


def assert_target_presence(arg0, scan1, arg2, arg3):
    assert arg0 in scan1.target
    assert arg2 not in scan1.target
    assert arg3 in scan1.target
