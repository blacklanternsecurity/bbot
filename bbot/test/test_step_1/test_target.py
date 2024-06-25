from ..bbot_fixtures import *  # noqa: F401


@pytest.mark.asyncio
async def test_target(bbot_scanner):
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

    bbottarget1 = BBOTTarget("evilcorp.com", "evilcorp.net", whitelist=["1.2.3.4/24"], blacklist=["1.2.3.4"])
    bbottarget2 = BBOTTarget("evilcorp.com", "evilcorp.net", whitelist=["1.2.3.0/24"], blacklist=["1.2.3.4"])
    bbottarget3 = BBOTTarget("evilcorp.com", whitelist=["1.2.3.4/24"], blacklist=["1.2.3.4"])
    bbottarget5 = BBOTTarget("evilcorp.com", "evilcorp.net", whitelist=["1.2.3.0/24"], blacklist=["1.2.3.4"])
    bbottarget6 = BBOTTarget(
        "evilcorp.com", "evilcorp.net", whitelist=["1.2.3.0/24"], blacklist=["1.2.3.4"], strict_scope=True
    )
    bbottarget8 = BBOTTarget("1.2.3.0/24", whitelist=["evilcorp.com", "evilcorp.net"], blacklist=["1.2.3.4"])
    bbottarget9 = BBOTTarget("evilcorp.com", "evilcorp.net", whitelist=["1.2.3.0/24"], blacklist=["1.2.3.4"])

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

    bbottarget10 = bbottarget9.copy()
    assert bbottarget10 == bbottarget9
    assert bbottarget9 == bbottarget10

    # make sure duplicate events don't change hash
    target1 = Target("https://evilcorp.com")
    target2 = Target("https://evilcorp.com")
    assert target1 == target2
    target1.add("https://evilcorp.com:443")
    assert target1 == target2

    # make sure hosts are collapsed in whitelist and blacklist
    bbottarget = BBOTTarget(
        "http://evilcorp.com:8080",
        whitelist=["evilcorp.net:443", "http://evilcorp.net:8080"],
        blacklist=["http://evilcorp.org:8080", "evilcorp.org:443"],
    )
    assert list(bbottarget) == ["http://evilcorp.com:8080"]
    assert list(bbottarget.seeds) == ["http://evilcorp.com:8080"]
    assert list(bbottarget.whitelist) == ["evilcorp.net"]
    assert list(bbottarget.blacklist) == ["evilcorp.org"]

    scan = bbot_scanner("ORG:evilcorp")
    events = [e async for e in scan.async_start()]
    assert len(events) == 2
    assert set([e.type for e in events]) == {"SCAN", "ORG_STUB"}

    # verify hash values
    bbottarget = BBOTTarget(
        "1.2.3.0/24",
        "http://www.evilcorp.net",
        "bob@fdsa.evilcorp.net",
        whitelist=["evilcorp.com", "bob@www.evilcorp.com", "evilcorp.net"],
        blacklist=["1.2.3.4", "4.3.2.1/24", "http://1.2.3.4", "bob@asdf.evilcorp.net"],
    )
    assert bbottarget.hash == b"\x8dW\xcbA\x0c\xc5\r\xc0\xfa\xae\xcd\xfc\x8e[<\xb5\x06\xc87\xf9"
    assert bbottarget.scope_hash == b"/\xce\xbf\x013\xb2\xb8\xf6\xbe_@\xae\xfc\x17w]\x85\x15N9"
    assert bbottarget.seeds.hash == b"\xaf.\x86\x83\xa1C\xad\xb4\xe7`X\x94\xe2\xa0\x01\xc2\xe3:J\xc5"
    assert bbottarget.whitelist.hash == b"b\x95\xc5\xf0hQ\x0c\x08\x92}\xa55\xff\x83\xf9'\x93\x927\xcb"
    assert bbottarget.blacklist.hash == b"\xaf\x0e\x8a\xe9JZ\x86\xbe\xee\xa9\xa9\xdb0\xaf'#\x84 U/"

    scan = bbot_scanner(
        "http://www.evilcorp.net",
        "1.2.3.0/24",
        "bob@fdsa.evilcorp.net",
        whitelist=["evilcorp.net", "evilcorp.com", "bob@www.evilcorp.com"],
        blacklist=["bob@asdf.evilcorp.net", "1.2.3.4", "4.3.2.1/24", "http://1.2.3.4"],
    )
    events = [e async for e in scan.async_start()]
    scan_events = [e for e in events if e.type == "SCAN"]
    assert len(scan_events) == 1
    assert (
        scan_events[0].data["target_hash"] == b"\x8dW\xcbA\x0c\xc5\r\xc0\xfa\xae\xcd\xfc\x8e[<\xb5\x06\xc87\xf9".hex()
    )
    assert scan_events[0].data["scope_hash"] == b"/\xce\xbf\x013\xb2\xb8\xf6\xbe_@\xae\xfc\x17w]\x85\x15N9".hex()
    assert scan_events[0].data["seed_hash"] == b"\xaf.\x86\x83\xa1C\xad\xb4\xe7`X\x94\xe2\xa0\x01\xc2\xe3:J\xc5".hex()
    assert (
        scan_events[0].data["whitelist_hash"] == b"b\x95\xc5\xf0hQ\x0c\x08\x92}\xa55\xff\x83\xf9'\x93\x927\xcb".hex()
    )
    assert scan_events[0].data["blacklist_hash"] == b"\xaf\x0e\x8a\xe9JZ\x86\xbe\xee\xa9\xa9\xdb0\xaf'#\x84 U/".hex()
    assert scan_events[0].data["target_hash"] == "8d57cb410cc50dc0faaecdfc8e5b3cb506c837f9"
    assert scan_events[0].data["scope_hash"] == "2fcebf0133b2b8f6be5f40aefc17775d85154e39"
    assert scan_events[0].data["seed_hash"] == "af2e8683a143adb4e7605894e2a001c2e33a4ac5"
    assert scan_events[0].data["whitelist_hash"] == "6295c5f068510c08927da535ff83f927939237cb"
    assert scan_events[0].data["blacklist_hash"] == "af0e8ae94a5a86beeea9a9db30af27238420552f"
