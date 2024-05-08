from ..bbot_fixtures import *  # noqa: F401


def test_target(bbot_scanner):
    scan1 = bbot_scanner("api.publicapis.org", "8.8.8.8/30", "2001:4860:4860::8888/126")
    scan2 = bbot_scanner("8.8.8.8/29", "publicapis.org", "2001:4860:4860::8888/125")
    scan3 = bbot_scanner("8.8.8.8/29", "publicapis.org", "2001:4860:4860::8888/125")
    scan4 = bbot_scanner("8.8.8.8/29")
    scan5 = bbot_scanner()
    assert not scan5.target
    assert len(scan1.target) == 9
    assert len(scan4.target) == 8
    assert "8.8.8.9" in scan1.target
    assert "8.8.8.12" not in scan1.target
    assert "8.8.8.8/31" in scan1.target
    assert "8.8.8.8/30" in scan1.target
    assert "8.8.8.8/29" not in scan1.target
    assert "2001:4860:4860::8889" in scan1.target
    assert "2001:4860:4860::888c" not in scan1.target
    assert "www.api.publicapis.org" in scan1.target
    assert "api.publicapis.org" in scan1.target
    assert "publicapis.org" not in scan1.target
    assert "bob@www.api.publicapis.org" in scan1.target
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

    from bbot.scanner.target import Target

    target = Target("evilcorp.com")
    assert not "com" in target
    assert "evilcorp.com" in target
    assert "www.evilcorp.com" in target
    strict_target = Target("evilcorp.com", strict_scope=True)
    assert not "com" in strict_target
    assert "evilcorp.com" in strict_target
    assert not "www.evilcorp.com" in strict_target

    target = Target()
    target.add("evilcorp.com")
    assert not "com" in target
    assert "evilcorp.com" in target
    assert "www.evilcorp.com" in target
    strict_target = Target(strict_scope=True)
    strict_target.add("evilcorp.com")
    assert not "com" in strict_target
    assert "evilcorp.com" in strict_target
    assert not "www.evilcorp.com" in strict_target
