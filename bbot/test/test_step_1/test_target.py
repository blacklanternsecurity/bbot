from ..bbot_fixtures import *  # noqa: F401


@pytest.mark.asyncio
async def test_target_basic(bbot_scanner):
    from radixtarget import RadixTarget
    from ipaddress import ip_address, ip_network
    from bbot.scanner.target import BBOTTarget, ScanSeeds

    scan1 = bbot_scanner("api.publicapis.org", "8.8.8.8/30", "2001:4860:4860::8888/126")
    scan2 = bbot_scanner("8.8.8.8/29", "publicapis.org", "2001:4860:4860::8888/125")
    scan3 = bbot_scanner("8.8.8.8/29", "publicapis.org", "2001:4860:4860::8888/125")
    scan4 = bbot_scanner("8.8.8.8/29")
    scan5 = bbot_scanner()

    # test different types of inputs
    target = BBOTTarget("evilcorp.com", "1.2.3.4/8")
    assert "www.evilcorp.com" in target.seeds
    assert "www.evilcorp.com:80" in target.seeds
    assert "http://www.evilcorp.com:80" in target.seeds
    assert "1.2.3.4" in target.seeds
    assert "1.2.3.4/24" in target.seeds
    assert ip_address("1.2.3.4") in target.seeds
    assert ip_network("1.2.3.4/24", strict=False) in target.seeds
    event = scan1.make_event("https://www.evilcorp.com:80", dummy=True)
    assert event in target.seeds
    with pytest.raises(ValueError):
        ["asdf"] in target.seeds
    with pytest.raises(ValueError):
        target.seeds.get(["asdf"])

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
    assert scan1.target.seeds in scan2.target.seeds
    assert scan2.target.seeds not in scan1.target.seeds
    assert scan3.target.seeds in scan2.target.seeds
    assert scan2.target.seeds == scan3.target.seeds
    assert scan4.target.seeds != scan1.target.seeds

    assert not scan5.target.whitelist
    assert len(scan1.target.whitelist) == 9
    assert len(scan4.target.whitelist) == 8
    assert "8.8.8.9" in scan1.target.whitelist
    assert "8.8.8.12" not in scan1.target.whitelist
    assert "8.8.8.8/31" in scan1.target.whitelist
    assert "8.8.8.8/30" in scan1.target.whitelist
    assert "8.8.8.8/29" not in scan1.target.whitelist
    assert "2001:4860:4860::8889" in scan1.target.whitelist
    assert "2001:4860:4860::888c" not in scan1.target.whitelist
    assert "www.api.publicapis.org" in scan1.target.whitelist
    assert "api.publicapis.org" in scan1.target.whitelist
    assert "publicapis.org" not in scan1.target.whitelist
    assert "bob@www.api.publicapis.org" in scan1.target.whitelist
    assert "https://www.api.publicapis.org" in scan1.target.whitelist
    assert "www.api.publicapis.org:80" in scan1.target.whitelist
    assert scan1.make_event("https://[2001:4860:4860::8888]:80", dummy=True) in scan1.target.whitelist
    assert scan1.make_event("[2001:4860:4860::8888]:80", "OPEN_TCP_PORT", dummy=True) in scan1.target.whitelist
    assert scan1.make_event("[2001:4860:4860::888c]:80", "OPEN_TCP_PORT", dummy=True) not in scan1.target.whitelist
    assert scan1.target.whitelist in scan2.target.whitelist
    assert scan2.target.whitelist not in scan1.target.whitelist
    assert scan3.target.whitelist in scan2.target.whitelist
    assert scan2.target.whitelist == scan3.target.whitelist
    assert scan4.target.whitelist != scan1.target.whitelist

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

    assert str(scan1.target.seeds.get("8.8.8.9").host) == "8.8.8.8/30"
    assert str(scan1.target.whitelist.get("8.8.8.9").host) == "8.8.8.8/30"
    assert scan1.target.seeds.get("8.8.8.12") is None
    assert scan1.target.whitelist.get("8.8.8.12") is None
    assert str(scan1.target.seeds.get("2001:4860:4860::8889").host) == "2001:4860:4860::8888/126"
    assert str(scan1.target.whitelist.get("2001:4860:4860::8889").host) == "2001:4860:4860::8888/126"
    assert scan1.target.seeds.get("2001:4860:4860::888c") is None
    assert scan1.target.whitelist.get("2001:4860:4860::888c") is None
    assert str(scan1.target.seeds.get("www.api.publicapis.org").host) == "api.publicapis.org"
    assert str(scan1.target.whitelist.get("www.api.publicapis.org").host) == "api.publicapis.org"
    assert scan1.target.seeds.get("publicapis.org") is None
    assert scan1.target.whitelist.get("publicapis.org") is None

    target = RadixTarget("evilcorp.com")
    assert "com" not in target
    assert "evilcorp.com" in target
    assert "www.evilcorp.com" in target
    strict_target = RadixTarget("evilcorp.com", strict_dns_scope=True)
    assert "com" not in strict_target
    assert "evilcorp.com" in strict_target
    assert "www.evilcorp.com" not in strict_target

    target = RadixTarget()
    target.add("evilcorp.com")
    assert "com" not in target
    assert "evilcorp.com" in target
    assert "www.evilcorp.com" in target
    strict_target = RadixTarget(strict_dns_scope=True)
    strict_target.add("evilcorp.com")
    assert "com" not in strict_target
    assert "evilcorp.com" in strict_target
    assert "www.evilcorp.com" not in strict_target

    # test target hashing

    target1 = BBOTTarget()
    target1.whitelist.add("evilcorp.com")
    target1.whitelist.add("1.2.3.4/24")
    target1.whitelist.add("https://evilcorp.net:8080")
    target1.seeds.add("evilcorp.com")
    target1.seeds.add("1.2.3.4/24")
    target1.seeds.add("https://evilcorp.net:8080")

    target2 = BBOTTarget()
    target2.whitelist.add("bob@evilcorp.org")
    target2.whitelist.add("evilcorp.com")
    target2.whitelist.add("1.2.3.4/24")
    target2.whitelist.add("https://evilcorp.net:8080")
    target2.seeds.add("bob@evilcorp.org")
    target2.seeds.add("evilcorp.com")
    target2.seeds.add("1.2.3.4/24")
    target2.seeds.add("https://evilcorp.net:8080")

    # make sure it's a sha1 hash
    assert isinstance(target1.hash, bytes)
    assert len(target1.hash) == 20

    # hashes shouldn't match yet
    assert target1.hash != target2.hash
    assert target1.scope_hash != target2.scope_hash
    # add missing email
    target1.whitelist.add("bob@evilcorp.org")
    assert target1.hash != target2.hash
    assert target1.scope_hash == target2.scope_hash
    target1.seeds.add("bob@evilcorp.org")
    # now they should match
    assert target1.hash == target2.hash

    # test default whitelist
    bbottarget = BBOTTarget("http://1.2.3.4:8443", "bob@evilcorp.com")
    assert bbottarget.seeds.hosts == {ip_network("1.2.3.4"), "evilcorp.com"}
    assert bbottarget.whitelist.hosts == {ip_network("1.2.3.4"), "evilcorp.com"}
    assert {e.data for e in bbottarget.seeds.events} == {"http://1.2.3.4:8443/", "bob@evilcorp.com"}
    assert {e.data for e in bbottarget.whitelist.events} == {"1.2.3.4", "evilcorp.com"}

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
    # 1 and 3 have different seeds
    assert bbottarget1 != bbottarget3
    assert bbottarget3 != bbottarget1
    # until we make them the same
    bbottarget3.seeds.add("evilcorp.net")
    assert bbottarget1 == bbottarget3
    assert bbottarget3 == bbottarget1

    # adding different events (but with same host) to whitelist should not change hash (since only hosts matter)
    bbottarget1.whitelist.add("http://evilcorp.co.nz")
    bbottarget2.whitelist.add("evilcorp.co.nz")
    assert bbottarget1 == bbottarget2
    assert bbottarget2 == bbottarget1

    # but seeds should change hash
    bbottarget1.seeds.add("http://evilcorp.co.nz")
    bbottarget2.seeds.add("evilcorp.co.nz")
    assert bbottarget1 != bbottarget2
    assert bbottarget2 != bbottarget1

    # make sure strict_scope is considered in hash
    assert bbottarget5 != bbottarget6
    assert bbottarget6 != bbottarget5

    # make sure swapped target <--> whitelist result in different hash
    assert bbottarget8 != bbottarget9
    assert bbottarget9 != bbottarget8

    # make sure duplicate events don't change hash
    target1 = BBOTTarget("https://evilcorp.com")
    target2 = BBOTTarget("https://evilcorp.com")
    assert target1 == target2
    target1.seeds.add("https://evilcorp.com:443")
    assert target1 == target2

    # make sure hosts are collapsed in whitelist and blacklist
    bbottarget = BBOTTarget(
        "http://evilcorp.com:8080",
        whitelist=["evilcorp.net:443", "http://evilcorp.net:8080"],
        blacklist=["http://evilcorp.org:8080", "evilcorp.org:443"],
    )
    # base class is not iterable
    with pytest.raises(TypeError):
        assert list(bbottarget) == ["http://evilcorp.com:8080"]
    assert list(bbottarget.seeds) == ["http://evilcorp.com:8080"]
    assert {e.data for e in bbottarget.whitelist} == {"evilcorp.net:443", "http://evilcorp.net:8080/"}
    assert {e.data for e in bbottarget.blacklist} == {"http://evilcorp.org:8080/", "evilcorp.org:443"}

    # test org stub as target
    for org_target in ("ORG:evilcorp", "ORG_STUB:evilcorp"):
        scan = bbot_scanner(org_target)
        events = [e async for e in scan.async_start()]
        assert len(events) == 3
        assert {e.type for e in events} == {"SCAN", "ORG_STUB"}

    # test username as target
    for user_target in ("USER:vancerefrigeration", "USERNAME:vancerefrigeration"):
        scan = bbot_scanner(user_target)
        events = [e async for e in scan.async_start()]
        assert len(events) == 3
        assert {e.type for e in events} == {"SCAN", "USERNAME"}

    # users + orgs + domains
    scan = bbot_scanner("USER:evilcorp", "ORG:evilcorp", "evilcorp.com")
    await scan.helpers.dns._mock_dns(
        {
            "evilcorp.com": {"A": ["1.2.3.4"]},
        },
    )
    events = [e async for e in scan.async_start()]
    assert len(events) == 5
    assert {e.type for e in events} == {"SCAN", "USERNAME", "ORG_STUB", "DNS_NAME"}

    # verify hash values
    bbottarget = BBOTTarget(
        "1.2.3.0/24",
        "http://www.evilcorp.net",
        "bob@fdsa.evilcorp.net",
        whitelist=["evilcorp.com", "bob@www.evilcorp.com", "evilcorp.net"],
        blacklist=["1.2.3.4", "4.3.2.1/24", "http://1.2.3.4", "bob@asdf.evilcorp.net"],
    )
    assert {e.data for e in bbottarget.seeds.events} == {
        "1.2.3.0/24",
        "http://www.evilcorp.net/",
        "bob@fdsa.evilcorp.net",
    }
    assert {e.data for e in bbottarget.whitelist.events} == {
        "evilcorp.com",
        "evilcorp.net",
        "bob@www.evilcorp.com",
    }
    assert {e.data for e in bbottarget.blacklist.events} == {
        "1.2.3.4",
        "4.3.2.0/24",
        "http://1.2.3.4/",
        "bob@asdf.evilcorp.net",
    }
    assert set(bbottarget.seeds.hosts) == {ip_network("1.2.3.0/24"), "www.evilcorp.net", "fdsa.evilcorp.net"}
    assert set(bbottarget.whitelist.hosts) == {"evilcorp.com", "evilcorp.net"}
    assert set(bbottarget.blacklist.hosts) == {ip_network("1.2.3.4/32"), ip_network("4.3.2.0/24"), "asdf.evilcorp.net"}
    assert bbottarget.hash == b"\xb3iU\xa8#\x8aq\x84/\xc5\xf2;\x11\x11\x0c&\xea\x07\xd4Q"
    assert bbottarget.scope_hash == b"f\xe1\x01c^3\xf5\xd24B\x87P\xa0Glq0p3J"
    assert bbottarget.seeds.hash == b"V\n\xf5\x1d\x1f=i\xbc\\\x15o\xc2p\xb2\x84\x97\xfeR\xde\xc1"
    assert bbottarget.whitelist.hash == b"\x8e\xd0\xa76\x8em4c\x0e\x1c\xfdA\x9d*sv}\xeb\xc4\xc4"
    assert bbottarget.blacklist.hash == b'\xf7\xaf\xa1\xda4"C:\x13\xf42\xc3,\xc3\xa9\x9f\x15\x15n\\'

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

    assert target_dict["seeds"] == ["1.2.3.0/24", "bob@fdsa.evilcorp.net", "http://www.evilcorp.net/"]
    assert target_dict["whitelist"] == ["bob@www.evilcorp.com", "evilcorp.com", "evilcorp.net"]
    assert target_dict["blacklist"] == ["1.2.3.4", "4.3.2.0/24", "bob@asdf.evilcorp.net", "http://1.2.3.4/"]
    assert target_dict["strict_scope"] is False
    assert target_dict["hash"] == "b36955a8238a71842fc5f23b11110c26ea07d451"
    assert target_dict["seed_hash"] == "560af51d1f3d69bc5c156fc270b28497fe52dec1"
    assert target_dict["whitelist_hash"] == "8ed0a7368e6d34630e1cfd419d2a73767debc4c4"
    assert target_dict["blacklist_hash"] == "f7afa1da3422433a13f432c32cc3a99f15156e5c"
    assert target_dict["scope_hash"] == "66e101635e33f5d234428750a0476c713070334a"

    # make sure child subnets/IPs don't get added to whitelist/blacklist
    target = RadixTarget("1.2.3.4/24", "1.2.3.4/28", acl_mode=True)
    assert set(target) == {ip_network("1.2.3.0/24")}
    target = RadixTarget("1.2.3.4/28", "1.2.3.4/24", acl_mode=True)
    assert set(target) == {ip_network("1.2.3.0/24")}
    target = RadixTarget("1.2.3.4/28", "1.2.3.4", acl_mode=True)
    assert set(target) == {ip_network("1.2.3.0/28")}
    target = RadixTarget("1.2.3.4", "1.2.3.4/28", acl_mode=True)
    assert set(target) == {ip_network("1.2.3.0/28")}

    # same but for domains
    target = RadixTarget("evilcorp.com", "www.evilcorp.com", acl_mode=True)
    assert set(target) == {"evilcorp.com"}
    target = RadixTarget("www.evilcorp.com", "evilcorp.com", acl_mode=True)
    assert set(target) == {"evilcorp.com"}

    # make sure strict_scope doesn't mess us up
    target = RadixTarget("evilcorp.co.uk", "www.evilcorp.co.uk", acl_mode=True, strict_dns_scope=True)
    assert set(target.hosts) == {"evilcorp.co.uk", "www.evilcorp.co.uk"}
    assert "evilcorp.co.uk" in target
    assert "www.evilcorp.co.uk" in target
    assert "api.evilcorp.co.uk" not in target
    assert "api.www.evilcorp.co.uk" not in target

    # test 'single' boolean argument
    target = ScanSeeds("http://evilcorp.com", "evilcorp.com:443")
    assert "www.evilcorp.com" in target
    assert "bob@evilcorp.com" in target
    event = target.get("www.evilcorp.com")
    assert event.host == "evilcorp.com"
    events = target.get("www.evilcorp.com", single=False)
    assert len(events) == 2
    assert {e.data for e in events} == {"http://evilcorp.com/", "evilcorp.com:443"}


@pytest.mark.asyncio
async def test_blacklist_regex(bbot_scanner, bbot_httpserver):
    from bbot.scanner.target import ScanBlacklist

    blacklist = ScanBlacklist("evilcorp.com")
    assert blacklist.inputs == {"evilcorp.com"}
    assert "www.evilcorp.com" in blacklist
    assert "http://www.evilcorp.com" in blacklist
    blacklist.add("RE:test")
    assert "RE:test" in blacklist.inputs
    assert set(blacklist.inputs) == {"evilcorp.com", "RE:test"}
    assert blacklist.blacklist_regexes
    assert next(iter(blacklist.blacklist_regexes)).pattern == "test"
    result1 = blacklist.get("test.com")
    assert result1.type == "DNS_NAME"
    assert result1.data == "test.com"
    result2 = blacklist.get("www.evilcorp.com")
    assert result2.type == "DNS_NAME"
    assert result2.data == "evilcorp.com"
    result2 = blacklist.get("www.evil.com")
    assert result2 is None
    with pytest.raises(KeyError):
        blacklist.get("www.evil.com", raise_error=True)
    assert "test.com" in blacklist
    assert "http://evilcorp.com/test.aspx" in blacklist
    assert "http://tes.com" not in blacklist

    blacklist = ScanBlacklist("evilcorp.com", r"RE:[0-9]{6}\.aspx$")
    assert "http://evilcorp.com" in blacklist
    assert "http://test.com/123456" not in blacklist
    assert "http://test.com/12345.aspx?a=asdf" not in blacklist
    assert "http://test.com/asdf/123456.aspx/asdf" not in blacklist
    assert "http://test.com/asdf/123456.aspx?a=asdf" in blacklist
    assert "http://test.com/asdf/123456.aspx" in blacklist

    bbot_httpserver.expect_request(uri="/").respond_with_data(
        """
        <a href='http://127.0.0.1:8888/asdfevil333asdf'/>
        <a href='http://127.0.0.1:8888/logout.aspx'/>
    """
    )
    bbot_httpserver.expect_request(uri="/asdfevilasdf").respond_with_data("")
    bbot_httpserver.expect_request(uri="/logout.aspx").respond_with_data("")

    # make sure URL is detected normally
    scan = bbot_scanner("http://127.0.0.1:8888/", presets=["spider"], config={"excavate": True}, debug=True)
    assert {r.pattern for r in scan.target.blacklist.blacklist_regexes} == {r"/.*(sign|log)[_-]?out"}
    events = [e async for e in scan.async_start()]
    urls = [e.data for e in events if e.type == "URL"]
    assert len(urls) == 2
    assert set(urls) == {"http://127.0.0.1:8888/", "http://127.0.0.1:8888/asdfevil333asdf"}

    # same scan again but with blacklist regex
    scan = bbot_scanner(
        "http://127.0.0.1:8888/",
        blacklist=[r"RE:evil[0-9]{3}"],
        presets=["spider"],
        config={"excavate": True},
        debug=True,
    )
    assert len(scan.target.blacklist) == 2
    assert scan.target.blacklist.blacklist_regexes
    assert {r.pattern for r in scan.target.blacklist.blacklist_regexes} == {
        r"evil[0-9]{3}",
        r"/.*(sign|log)[_-]?out",
    }
    events = [e async for e in scan.async_start()]
    urls = [e.data for e in events if e.type == "URL"]
    assert len(urls) == 1
    assert set(urls) == {"http://127.0.0.1:8888/"}
