from ..bbot_fixtures import *  # noqa: F401


@pytest.mark.asyncio
async def test_target(bbot_scanner):
    import random
    from ipaddress import ip_address, ip_network
    from bbot.scanner.target import Target, BBOTTarget

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

    # test org stub as target
    for org_target in ("ORG:evilcorp", "ORG_STUB:evilcorp"):
        scan = bbot_scanner(org_target)
        events = [e async for e in scan.async_start()]
        assert len(events) == 3
        assert set([e.type for e in events]) == {"SCAN", "ORG_STUB"}

    # test username as target
    for user_target in ("USER:vancerefrigeration", "USERNAME:vancerefrigeration"):
        scan = bbot_scanner(user_target)
        events = [e async for e in scan.async_start()]
        assert len(events) == 3
        assert set([e.type for e in events]) == {"SCAN", "USERNAME"}

    # verify hash values
    bbottarget = BBOTTarget(
        "1.2.3.0/24",
        "http://www.evilcorp.net",
        "bob@fdsa.evilcorp.net",
        whitelist=["evilcorp.com", "bob@www.evilcorp.com", "evilcorp.net"],
        blacklist=["1.2.3.4", "4.3.2.1/24", "http://1.2.3.4", "bob@asdf.evilcorp.net"],
    )
    assert set([e.data for e in bbottarget.seeds.events]) == {
        "1.2.3.0/24",
        "http://www.evilcorp.net/",
        "bob@fdsa.evilcorp.net",
    }
    assert set([e.data for e in bbottarget.whitelist.events]) == {"evilcorp.com", "evilcorp.net"}
    assert set([e.data for e in bbottarget.blacklist.events]) == {"1.2.3.4", "4.3.2.0/24", "asdf.evilcorp.net"}
    assert set(bbottarget.seeds.hosts) == {ip_network("1.2.3.0/24"), "www.evilcorp.net", "fdsa.evilcorp.net"}
    assert set(bbottarget.whitelist.hosts) == {"evilcorp.com", "evilcorp.net"}
    assert set(bbottarget.blacklist.hosts) == {ip_address("1.2.3.4"), ip_network("4.3.2.0/24"), "asdf.evilcorp.net"}
    assert bbottarget.hash == b"\x0b\x908\xe3\xef\n=\x13d\xdf\x00;\xack\x0c\xbc\xd2\xcc'\xba"
    assert bbottarget.scope_hash == b"\x00\xf5V\xfb.\xeb#\xcb\xf0q\xf9\xe9e\xb7\x1f\xe2T+\xdbw"
    assert bbottarget.seeds.hash == b"\xaf.\x86\x83\xa1C\xad\xb4\xe7`X\x94\xe2\xa0\x01\xc2\xe3:J\xc5"
    assert bbottarget.whitelist.hash == b"\xa0Af\x07n\x10\xd9\xb6\n\xa7TO\xb07\xcdW\xc4vLC"
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
    assert len(scan_events) == 2
    target_dict = scan_events[0].data["target"]
    assert target_dict["strict_scope"] == False
    assert target_dict["hash"] == b"\x0b\x908\xe3\xef\n=\x13d\xdf\x00;\xack\x0c\xbc\xd2\xcc'\xba".hex()
    assert target_dict["scope_hash"] == b"\x00\xf5V\xfb.\xeb#\xcb\xf0q\xf9\xe9e\xb7\x1f\xe2T+\xdbw".hex()
    assert target_dict["seed_hash"] == b"\xaf.\x86\x83\xa1C\xad\xb4\xe7`X\x94\xe2\xa0\x01\xc2\xe3:J\xc5".hex()
    assert target_dict["whitelist_hash"] == b"\xa0Af\x07n\x10\xd9\xb6\n\xa7TO\xb07\xcdW\xc4vLC".hex()
    assert target_dict["blacklist_hash"] == b"\xaf\x0e\x8a\xe9JZ\x86\xbe\xee\xa9\xa9\xdb0\xaf'#\x84 U/".hex()
    assert target_dict["hash"] == "0b9038e3ef0a3d1364df003bac6b0cbcd2cc27ba"
    assert target_dict["scope_hash"] == "00f556fb2eeb23cbf071f9e965b71fe2542bdb77"
    assert target_dict["seed_hash"] == "af2e8683a143adb4e7605894e2a001c2e33a4ac5"
    assert target_dict["whitelist_hash"] == "a04166076e10d9b60aa7544fb037cd57c4764c43"
    assert target_dict["blacklist_hash"] == "af0e8ae94a5a86beeea9a9db30af27238420552f"

    # test target sorting
    big_subnet = scan.make_event("1.2.3.4/24", dummy=True)
    medium_subnet = scan.make_event("1.2.3.4/28", dummy=True)
    small_subnet = scan.make_event("1.2.3.4/30", dummy=True)
    ip_event = scan.make_event("1.2.3.4", dummy=True)
    parent_domain = scan.make_event("evilcorp.com", dummy=True)
    grandparent_domain = scan.make_event("www.evilcorp.com", dummy=True)
    greatgrandparent_domain = scan.make_event("api.www.evilcorp.com", dummy=True)
    target = Target()
    assert big_subnet._host_size == -256
    assert medium_subnet._host_size == -16
    assert small_subnet._host_size == -4
    assert ip_event._host_size == 1
    assert parent_domain._host_size == 12
    assert grandparent_domain._host_size == 16
    assert greatgrandparent_domain._host_size == 20
    events = [
        big_subnet,
        medium_subnet,
        small_subnet,
        ip_event,
        parent_domain,
        grandparent_domain,
        greatgrandparent_domain,
    ]
    random.shuffle(events)
    assert target._sort_events(events) == [
        big_subnet,
        medium_subnet,
        small_subnet,
        ip_event,
        parent_domain,
        grandparent_domain,
        greatgrandparent_domain,
    ]

    # make sure child subnets/IPs don't get added to whitelist/blacklist
    target = Target("1.2.3.4/24", "1.2.3.4/28", acl_mode=True)
    assert set(e.data for e in target) == {"1.2.3.0/24"}
    target = Target("1.2.3.4/28", "1.2.3.4/24", acl_mode=True)
    assert set(e.data for e in target) == {"1.2.3.0/24"}
    target = Target("1.2.3.4/28", "1.2.3.4", acl_mode=True)
    assert set(e.data for e in target) == {"1.2.3.0/28"}
    target = Target("1.2.3.4", "1.2.3.4/28", acl_mode=True)
    assert set(e.data for e in target) == {"1.2.3.0/28"}

    # same but for domains
    target = Target("evilcorp.com", "www.evilcorp.com", acl_mode=True)
    assert set(e.data for e in target) == {"evilcorp.com"}
    target = Target("www.evilcorp.com", "evilcorp.com", acl_mode=True)
    assert set(e.data for e in target) == {"evilcorp.com"}

    # make sure strict_scope doesn't mess us up
    target = Target("evilcorp.co.uk", "www.evilcorp.co.uk", acl_mode=True, strict_scope=True)
    assert set(target.hosts) == {"evilcorp.co.uk", "www.evilcorp.co.uk"}
    assert "evilcorp.co.uk" in target
    assert "www.evilcorp.co.uk" in target
    assert not "api.evilcorp.co.uk" in target
    assert not "api.www.evilcorp.co.uk" in target

    # test 'single' boolean argument
    target = Target("http://evilcorp.com", "evilcorp.com:443")
    assert "www.evilcorp.com" in target
    event = target.get("www.evilcorp.com")
    assert event.host == "evilcorp.com"
    events = target.get("www.evilcorp.com", single=False)
    assert len(events) == 2
    assert set([e.data for e in events]) == {"http://evilcorp.com/", "evilcorp.com:443"}
