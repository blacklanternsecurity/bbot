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

    assert not scan5.target.seeds
    assert len(scan1.target.seeds) == 9
    assert len(scan4.target.seeds) == 8
    assert "8.8.8.9" in scan1.target.seeds
    assert "8.8.8.12" not in scan1.target.seeds
    assert "8.8.8.8/31" in scan1.target.seeds
    assert "8.8.8.8/30" in scan1.target.seeds
    assert "8.8.8.8/29" not in scan1.target.seeds
    assert "2001:4860:4860::8889" in scan1.target.seeds
    assert "2001:4860:4860::888c" not in scan1.target.seeds
    assert "www.api.publicapis.org" in scan1.target.seeds
    assert "api.publicapis.org" in scan1.target.seeds
    assert "publicapis.org" not in scan1.target.seeds
    assert "bob@www.api.publicapis.org" in scan1.target.seeds
    assert "https://www.api.publicapis.org" in scan1.target.seeds
    assert "www.api.publicapis.org:80" in scan1.target.seeds
    assert scan1.make_event("https://[2001:4860:4860::8888]:80", dummy=True) in scan1.target.seeds
    assert scan1.make_event("[2001:4860:4860::8888]:80", "OPEN_TCP_PORT", dummy=True) in scan1.target.seeds
    assert scan1.make_event("[2001:4860:4860::888c]:80", "OPEN_TCP_PORT", dummy=True) not in scan1.target.seeds

    assert scan1.whitelisted("https://[2001:4860:4860::8888]:80")
    assert scan1.whitelisted("[2001:4860:4860::8888]:80")
    assert not scan1.whitelisted("[2001:4860:4860::888c]:80")
    assert scan1.whitelisted("www.api.publicapis.org")
    assert scan1.whitelisted("api.publicapis.org")
    assert not scan1.whitelisted("publicapis.org")

    assert scan1.target.seeds in scan2.target.seeds
    assert scan2.target.seeds not in scan1.target.seeds
    assert scan3.target.seeds in scan2.target.seeds
    assert scan2.target.seeds == scan3.target.seeds
    assert scan4.target.seeds != scan1.target.seeds

    assert str(scan1.target.get("8.8.8.9").host) == "8.8.8.8/30"
    assert scan1.target.get("8.8.8.12") is None
    assert str(scan1.target.get("2001:4860:4860::8889").host) == "2001:4860:4860::8888/126"
    assert scan1.target.get("2001:4860:4860::888c") is None
    assert str(scan1.target.get("www.api.publicapis.org").host) == "api.publicapis.org"
    assert scan1.target.get("publicapis.org") is None

    from bbot.scanner.target import Target, BBOTTarget

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

    # test target hashing

    target1 = Target()
    target1.add("evilcorp.com")
    target1.add("1.2.3.4/24")
    target1.add("https://evilcorp.net:8080")

    target2 = Target()
    target2.add("bob@evilcorp.org")
    target2.add("evilcorp.com")
    target2.add("1.2.3.4/24")
    target2.add("https://evilcorp.net:8080")

    # make sure it's a sha1 hash
    assert isinstance(target1.hash, bytes)
    assert len(target1.hash) == 20

    # hashes shouldn't match yet
    assert target1.hash != target2.hash
    # add missing email
    target1.add("bob@evilcorp.org")
    # now they should match
    assert target1.hash == target2.hash

    bbottarget1 = BBOTTarget(["evilcorp.com", "evilcorp.net"], whitelist=["1.2.3.4/24"], blacklist=["1.2.3.4"])
    bbottarget2 = BBOTTarget(["evilcorp.com", "evilcorp.net"], whitelist=["1.2.3.0/24"], blacklist=["1.2.3.4"])
    bbottarget3 = BBOTTarget(["evilcorp.com"], whitelist=["1.2.3.4/24"], blacklist=["1.2.3.4"])
    bbottarget5 = BBOTTarget(["evilcorp.com", "evilcorp.net"], whitelist=["1.2.3.0/24"], blacklist=["1.2.3.4"])
    bbottarget6 = BBOTTarget(
        ["evilcorp.com", "evilcorp.net"], whitelist=["1.2.3.0/24"], blacklist=["1.2.3.4"], strict_scope=True
    )
    bbottarget8 = BBOTTarget(["1.2.3.0/24"], whitelist=["evilcorp.com", "evilcorp.net"], blacklist=["1.2.3.4"])
    bbottarget9 = BBOTTarget(["evilcorp.com", "evilcorp.net"], whitelist=["1.2.3.0/24"], blacklist=["1.2.3.4"])

    # make sure it's a sha1 hash
    assert isinstance(bbottarget1.hash, bytes)
    assert len(bbottarget1.hash) == 20

    assert bbottarget1 == bbottarget2
    assert bbottarget2 == bbottarget1
    assert bbottarget1 != bbottarget3
    assert bbottarget3 != bbottarget1
    bbottarget3.add("evilcorp.net")
    assert bbottarget1 == bbottarget3
    assert bbottarget3 == bbottarget1

    bbottarget1.add("http://evilcorp.co.nz")
    bbottarget2.add("evilcorp.co.nz")
    assert bbottarget1 != bbottarget2
    assert bbottarget2 != bbottarget1

    # make sure strict_scope is considered in hash
    assert bbottarget5 != bbottarget6
    assert bbottarget6 != bbottarget5

    # make sure swapped target <--> whitelist result in different hash
    assert bbottarget8 != bbottarget9
    assert bbottarget9 != bbottarget8

    # make sure duplicate events don't change hash
    target1 = Target("https://evilcorp.com")
    target2 = Target("https://evilcorp.com")
    assert target1 == target2
    target1.add("https://evilcorp.com:443")
    assert target1 == target2

    # make sure hosts are collapsed in whitslist and blacklist
    bbottarget = BBOTTarget(
        ["http://evilcorp.com:8080"],
        whitelist=["evilcorp.net:443", "http://evilcorp.net:8080"],
        blacklist=["http://evilcorp.org:8080", "evilcorp.org:443"],
    )
    assert list(bbottarget) == ["http://evilcorp.com:8080"]
    assert list(bbottarget.seeds) == ["http://evilcorp.com:8080"]
    assert list(bbottarget.whitelist) == ["evilcorp.net"]
    assert list(bbottarget.blacklist) == ["evilcorp.org"]
