from ..bbot_fixtures import *  # noqa: F401
from bbot.test.worker import HTTPSERVER_URL


@pytest.mark.asyncio
async def test_target_basic(bbot_scanner):
    from radixtarget import RadixTarget
    from ipaddress import ip_address, ip_network
    from bbot.scanner.target import BBOTTarget, ScanSeeds, ScanTarget

    scan1 = bbot_scanner("api.publicapis.org", "8.8.8.8/30", "2001:4860:4860::8888/126")
    scan2 = bbot_scanner("8.8.8.8/29", "publicapis.org", "2001:4860:4860::8888/125")
    scan3 = bbot_scanner("8.8.8.8/29", "publicapis.org", "2001:4860:4860::8888/125")
    scan4 = bbot_scanner("8.8.8.8/29")
    scan5 = bbot_scanner()

    await scan1._prep()
    await scan2._prep()
    await scan3._prep()
    await scan4._prep()
    await scan5._prep()

    # test different types of inputs
    target = BBOTTarget(target=["evilcorp.com", "1.2.3.4/8"])
    assert "www.evilcorp.com" in target.seeds
    assert "www.evilcorp.com:80" in target.seeds
    assert "http://www.evilcorp.com:80" in target.seeds
    assert "1.2.3.4" in target.seeds
    assert "1.2.3.4/24" in target.seeds
    assert ip_address("1.2.3.4") in target.seeds
    assert ip_network("1.2.3.4/24", strict=False) in target.seeds
    event = scan1.make_event("https://www.evilcorp.com:80", dummy=True)
    assert event in target.seeds
    assert ["asdf"] not in target.seeds
    assert target.seeds.get(["asdf"]) is None

    assert not scan5.target.seeds
    # radixtarget 4.x counts hosts/networks, not individual IPs
    assert len(scan1.target.seeds) == 3  # api.publicapis.org, 8.8.8.8/30, 2001:4860:4860::8888/126
    assert len(scan4.target.seeds) == 1  # 8.8.8.8/29
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

    assert not scan5.target.target
    assert len(scan1.target.target) == 3
    assert len(scan4.target.target) == 1
    assert "8.8.8.9" in scan1.target.target
    assert "8.8.8.12" not in scan1.target.target
    assert "8.8.8.8/31" in scan1.target.target
    assert "8.8.8.8/30" in scan1.target.target
    assert "8.8.8.8/29" not in scan1.target.target
    assert "2001:4860:4860::8889" in scan1.target.target
    assert "2001:4860:4860::888c" not in scan1.target.target
    assert "www.api.publicapis.org" in scan1.target.target
    assert "api.publicapis.org" in scan1.target.target
    assert "publicapis.org" not in scan1.target.target
    assert "bob@www.api.publicapis.org" in scan1.target.target
    assert "https://www.api.publicapis.org" in scan1.target.target
    assert "www.api.publicapis.org:80" in scan1.target.target
    assert scan1.make_event("https://[2001:4860:4860::8888]:80", dummy=True) in scan1.target.target
    assert scan1.make_event("[2001:4860:4860::8888]:80", "OPEN_TCP_PORT", dummy=True) in scan1.target.target
    assert scan1.make_event("[2001:4860:4860::888c]:80", "OPEN_TCP_PORT", dummy=True) not in scan1.target.target
    assert scan1.target.target in scan2.target.target
    assert scan2.target.target not in scan1.target.target
    assert scan3.target.target in scan2.target.target
    assert scan2.target.target == scan3.target.target
    assert scan4.target.target != scan1.target.target

    assert scan1.in_target("https://[2001:4860:4860::8888]:80")
    assert scan1.in_target("[2001:4860:4860::8888]:80")
    assert not scan1.in_target("[2001:4860:4860::888c]:80")
    assert scan1.in_target("www.api.publicapis.org")
    assert scan1.in_target("api.publicapis.org")
    assert not scan1.in_target("publicapis.org")

    assert scan1.target.seeds in scan2.target.seeds
    assert scan2.target.seeds not in scan1.target.seeds
    assert scan3.target.seeds in scan2.target.seeds
    assert scan2.target.seeds == scan3.target.seeds
    assert scan4.target.seeds != scan1.target.seeds

    assert str(scan1.target.seeds.get("8.8.8.9").host) == "8.8.8.8/30"
    assert str(scan1.target.target.get("8.8.8.9").host) == "8.8.8.8/30"
    assert scan1.target.seeds.get("8.8.8.12") is None
    assert scan1.target.target.get("8.8.8.12") is None
    assert str(scan1.target.seeds.get("2001:4860:4860::8889").host) == "2001:4860:4860::8888/126"
    assert str(scan1.target.target.get("2001:4860:4860::8889").host) == "2001:4860:4860::8888/126"
    assert scan1.target.seeds.get("2001:4860:4860::888c") is None
    assert scan1.target.target.get("2001:4860:4860::888c") is None
    assert str(scan1.target.seeds.get("www.api.publicapis.org").host) == "api.publicapis.org"
    assert str(scan1.target.target.get("www.api.publicapis.org").host) == "api.publicapis.org"
    assert scan1.target.seeds.get("publicapis.org") is None
    assert scan1.target.target.get("publicapis.org") is None

    target = RadixTarget("evilcorp.com")
    assert "com" not in target
    assert "evilcorp.com" in target
    assert "www.evilcorp.com" in target
    strict_target = RadixTarget("evilcorp.com", strict_scope=True)
    assert "com" not in strict_target
    assert "evilcorp.com" in strict_target
    assert "www.evilcorp.com" not in strict_target

    target = RadixTarget()
    target.add("evilcorp.com")
    assert "com" not in target
    assert "evilcorp.com" in target
    assert "www.evilcorp.com" in target
    strict_target = RadixTarget(strict_scope=True)
    strict_target.add("evilcorp.com")
    assert "com" not in strict_target
    assert "evilcorp.com" in strict_target
    assert "www.evilcorp.com" not in strict_target

    # test target hashing

    target1 = BBOTTarget()
    target1.target.add("evilcorp.com")
    target1.target.add("1.2.3.4/24")
    target1.target.add("https://evilcorp.net:8080")
    target1.seeds.add("evilcorp.com")
    target1.seeds.add("1.2.3.4/24")
    target1.seeds.add("https://evilcorp.net:8080")

    target2 = BBOTTarget()
    target2.target.add("bob@evilcorp.org")
    target2.target.add("evilcorp.com")
    target2.target.add("1.2.3.4/24")
    target2.target.add("https://evilcorp.net:8080")
    target2.seeds.add("bob@evilcorp.org")
    target2.seeds.add("evilcorp.com")
    target2.seeds.add("1.2.3.4/24")
    target2.seeds.add("https://evilcorp.net:8080")

    assert isinstance(target1.hash, bytes)
    assert len(target1.hash) == 24

    # hashes shouldn't match yet
    assert target1.hash != target2.hash
    assert target1.scope_hash != target2.scope_hash
    # add missing email
    target1.target.add("bob@evilcorp.org")
    assert target1.hash != target2.hash
    assert target1.scope_hash == target2.scope_hash
    target1.seeds.add("bob@evilcorp.org")
    # now they should match
    assert target1.hash == target2.hash

    # test default target
    bbottarget = BBOTTarget(target=["http://1.2.3.4:8443", "bob@evilcorp.com"])

    assert bbottarget.seeds.hosts == {"1.2.3.4/32", "evilcorp.com"}
    assert bbottarget.target.hosts == {"1.2.3.4/32", "evilcorp.com"}
    assert {e.data for e in bbottarget.seeds.event_seeds} == {"http://1.2.3.4:8443/", "bob@evilcorp.com"}
    assert {e.data for e in bbottarget.target.event_seeds} == {"http://1.2.3.4:8443/", "bob@evilcorp.com"}

    bbottarget1 = BBOTTarget(seeds=["evilcorp.com", "evilcorp.net"], target=["1.2.3.4/24"], blacklist=["1.2.3.4"])
    bbottarget2 = BBOTTarget(seeds=["evilcorp.com", "evilcorp.net"], target=["1.2.3.0/24"], blacklist=["1.2.3.4"])
    bbottarget3 = BBOTTarget(seeds=["evilcorp.com"], target=["1.2.3.4/24"], blacklist=["1.2.3.4"])
    bbottarget5 = BBOTTarget(seeds=["evilcorp.com", "evilcorp.net"], target=["1.2.3.0/24"], blacklist=["1.2.3.4"])
    bbottarget6 = BBOTTarget(
        seeds=["evilcorp.com", "evilcorp.net"], target=["1.2.3.0/24"], blacklist=["1.2.3.4"], strict_scope=True
    )
    bbottarget8 = BBOTTarget(seeds=["1.2.3.0/24"], target=["evilcorp.com", "evilcorp.net"], blacklist=["1.2.3.4"])
    bbottarget9 = BBOTTarget(seeds=["evilcorp.com", "evilcorp.net"], target=["1.2.3.0/24"], blacklist=["1.2.3.4"])

    assert isinstance(bbottarget1.hash, bytes)
    assert len(bbottarget1.hash) == 24

    assert bbottarget1 == bbottarget2
    assert bbottarget2 == bbottarget1
    # 1 and 3 have different seeds
    assert bbottarget1 != bbottarget3
    assert bbottarget3 != bbottarget1
    # until we make them the same
    bbottarget3.seeds.add("evilcorp.net")
    assert bbottarget1 == bbottarget3
    assert bbottarget3 == bbottarget1

    # adding different events (but with same host) to target should not change hash (since only hosts matter)
    bbottarget1.target.add("http://evilcorp.co.nz")
    bbottarget2.target.add("evilcorp.co.nz")
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

    # make sure swapped target <--> blacklist result in different hash
    assert bbottarget8 != bbottarget9
    assert bbottarget9 != bbottarget8

    # make sure duplicate events don't change hash
    target1 = BBOTTarget(target=["https://evilcorp.com"])
    target2 = BBOTTarget(target=["https://evilcorp.com"])
    assert target1 == target2
    target1.seeds.add("https://evilcorp.com:443")
    assert target1 == target2

    # make sure hosts are collapsed in target and blacklist
    bbottarget = BBOTTarget(
        seeds=["http://evilcorp.com:8080"],
        target=["evilcorp.net:443", "http://evilcorp.net:8080"],
        blacklist=["http://evilcorp.org:8080", "evilcorp.org:443"],
    )
    # base class is not iterable
    with pytest.raises(TypeError):
        assert list(bbottarget) == ["http://evilcorp.com:8080/"]
    assert {e.data for e in bbottarget.seeds} == {"http://evilcorp.com:8080/"}
    assert {e.data for e in bbottarget.target} == {"evilcorp.net:443", "http://evilcorp.net:8080/"}
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
    await scan._prep()
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
        seeds=["1.2.3.0/24", "http://www.evilcorp.net", "bob@fdsa.evilcorp.net"],
        target=["evilcorp.com", "bob@www.evilcorp.com", "evilcorp.net"],
        blacklist=["1.2.3.4", "4.3.2.1/24", "http://1.2.3.4", "bob@asdf.evilcorp.net"],
    )
    assert {e.data for e in bbottarget.seeds.event_seeds} == {
        "1.2.3.0/24",
        "http://www.evilcorp.net/",
        "bob@fdsa.evilcorp.net",
    }
    assert {e.data for e in bbottarget.target.event_seeds} == {
        "evilcorp.com",
        "evilcorp.net",
        "bob@www.evilcorp.com",
    }
    assert {e.data for e in bbottarget.blacklist.event_seeds} == {
        "1.2.3.4",
        "4.3.2.0/24",
        "http://1.2.3.4/",
        "bob@asdf.evilcorp.net",
    }
    assert bbottarget.seeds.hosts == {"1.2.3.0/24", "www.evilcorp.net", "fdsa.evilcorp.net"}
    assert set(bbottarget.target.hosts) == {"evilcorp.com", "evilcorp.net"}
    assert bbottarget.blacklist.hosts == {"1.2.3.4/32", "4.3.2.0/24", "asdf.evilcorp.net"}
    assert bbottarget.hash == b"W\x1ai\x9f\xd6\x13\x87\xdd\x9cNP\xcf\xca4[6F\xc0U\x13\xfbd\xd9\xf3"
    assert bbottarget.scope_hash == b"\x9cNP\xcf\xca4[6F\xc0U\x13\xfbd\xd9\xf3"
    assert bbottarget.seeds.hash == b"W\x1ai\x9f\xd6\x13\x87\xdd"
    assert bbottarget.target.hash == b"\x9cNP\xcf\xca4[6"
    assert bbottarget.blacklist.hash == b"F\xc0U\x13\xfbd\xd9\xf3"

    scan = bbot_scanner(
        "evilcorp.net",
        "evilcorp.com",
        "bob@www.evilcorp.com",
        seeds=["http://www.evilcorp.net", "1.2.3.0/24", "bob@fdsa.evilcorp.net"],
        blacklist=["bob@asdf.evilcorp.net", "1.2.3.4", "4.3.2.1/24", "http://1.2.3.4"],
    )
    events = [e async for e in scan.async_start()]
    scan_events = [e for e in events if e.type == "SCAN"]
    assert len(scan_events) == 2
    target_dict = scan_events[0].data["target"]

    assert target_dict["seeds"] == ["1.2.3.0/24", "bob@fdsa.evilcorp.net", "http://www.evilcorp.net/"]
    assert target_dict["target"] == ["bob@www.evilcorp.com", "evilcorp.com", "evilcorp.net"]
    assert target_dict["blacklist"] == ["1.2.3.4", "4.3.2.0/24", "bob@asdf.evilcorp.net", "http://1.2.3.4/"]
    assert target_dict["strict_scope"] is False
    assert target_dict["hash"] == "571a699fd61387dd9c4e50cfca345b3646c05513fb64d9f3"
    assert target_dict["seed_hash"] == "571a699fd61387dd"
    assert target_dict["target_hash"] == "9c4e50cfca345b36"
    assert target_dict["blacklist_hash"] == "46c05513fb64d9f3"
    assert target_dict["scope_hash"] == "9c4e50cfca345b3646c05513fb64d9f3"

    # make sure child subnets/IPs don't get added to target/blacklist
    target = RadixTarget("1.2.3.4/24", "1.2.3.4/28", acl_mode=True)
    assert set(target) == {"1.2.3.0/24"}
    target = RadixTarget("1.2.3.4/28", "1.2.3.4/24", acl_mode=True)
    assert set(target) == {"1.2.3.0/24"}
    target = RadixTarget("1.2.3.4/28", "1.2.3.4", acl_mode=True)
    assert set(target) == {"1.2.3.0/28"}
    target = RadixTarget("1.2.3.4", "1.2.3.4/28", acl_mode=True)
    assert set(target) == {"1.2.3.0/28"}

    # same but for domains
    target = RadixTarget("evilcorp.com", "www.evilcorp.com", acl_mode=True)
    assert set(target) == {"evilcorp.com"}
    target = RadixTarget("www.evilcorp.com", "evilcorp.com", acl_mode=True)
    assert set(target) == {"evilcorp.com"}

    # make sure strict_scope doesn't mess us up
    # radixtarget 4.x: strict_scope and acl_mode are mutually exclusive,
    # so ACLTarget skips acl_mode when strict_scope is True
    target = ScanTarget("evilcorp.co.uk", "www.evilcorp.co.uk", strict_scope=True)
    assert target.hosts == {"evilcorp.co.uk", "www.evilcorp.co.uk"}
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
async def test_asn_targets(bbot_scanner):
    """Test ASN target parsing, validation, and functionality."""
    from bbot.core.event.helpers import EventSeed
    from bbot.scanner.target import BBOTTarget

    # Test ASN target parsing with different formats
    for asn_format in ("ASN:15169", "AS:15169", "AS15169", "asn:15169", "as:15169", "as15169"):
        event_seed = EventSeed(asn_format)
        assert event_seed.type == "ASN"
        assert event_seed.data == "15169"
        assert event_seed.input == "ASN:15169"

    # Test ASN targets in BBOTTarget (target= is the primary input; seeds auto-populate from target)
    target = BBOTTarget(target=["ASN:15169"])
    assert "ASN:15169" in target.seeds.inputs

    # Test ASN with other targets
    target = BBOTTarget(target=["ASN:15169", "evilcorp.com", "1.2.3.4/24"])
    assert "ASN:15169" in target.seeds.inputs
    assert "evilcorp.com" in target.seeds.inputs
    assert "1.2.3.0/24" in target.seeds.inputs  # IP ranges are normalized to network address

    # Test ASN targets must be expanded before being useful in scope/blacklist
    # Direct ASN targets don't work since they have no host
    # Instead, test that the ASN input is captured correctly
    target = BBOTTarget(target=["evilcorp.com"])
    # ASN targets should be added to seeds
    target.seeds.add("ASN:15169")
    assert "ASN:15169" in target.seeds.inputs

    # Test ASN target expansion with real asndb (Google's AS15169)
    scan = bbot_scanner("ASN:15169")
    target = BBOTTarget(target=["ASN:15169"])

    # Verify initial state
    initial_hosts = len(target.seeds.hosts)
    initial_seeds = len(target.seeds.event_seeds)

    # Generate children (expand ASN to IP ranges)
    await target.generate_children(helpers=scan.helpers)

    # After expansion, should have additional IP range seeds
    assert len(target.seeds.event_seeds) > initial_seeds
    assert len(target.seeds.hosts) > initial_hosts

    # Google's AS15169 owns 8.8.8.0/24
    assert "8.8.8.0/24" in target.seeds.hosts
    assert "8.8.8.0/24" in target.target.hosts


@pytest.mark.asyncio
async def test_asn_targets_integration(bbot_scanner):
    """Test ASN targets with full scanner integration."""
    from unittest.mock import AsyncMock, MagicMock, patch

    mock_client = MagicMock()
    mock_client.lookup_asn = AsyncMock(
        return_value={
            "asn": 15169,
            "asn_name": "GOOGLE",
            "org": "Google LLC",
            "country": "US",
            "subnets": ["8.8.8.0/24", "8.8.4.0/24"],
        }
    )
    mock_client.cleanup = AsyncMock()

    # Create scanner with ASN target
    scan = bbot_scanner("ASN:15169")

    with patch("asndb.ASNDB", return_value=mock_client):
        # Initialize scan to access preset and target
        await scan._prep()

        # Verify target was parsed correctly
        assert "ASN:15169" in scan.preset.target.seeds.inputs

        # Verify expansion worked (generate_children is called during _prep)

        assert "8.8.8.0/24" in scan.preset.target.seeds.hosts
        assert "8.8.4.0/24" in scan.preset.target.seeds.hosts

        # Test scope checking with expanded ranges
        assert scan.in_scope("8.8.8.1")
        assert scan.in_scope("8.8.4.1")
        assert not scan.in_scope("1.1.1.1")


@pytest.mark.asyncio
async def test_asn_targets_edge_cases(bbot_scanner):
    """Test edge cases and error handling for ASN targets."""
    from bbot.core.event.helpers import EventSeed
    from bbot.errors import ValidationError
    from bbot.scanner.target import BBOTTarget

    # Test invalid ASN formats that should raise ValidationError
    invalid_formats_validation_error = ["ASN:", "AS:", "ASN:abc", "AS:xyz", "ASN:-1"]
    for invalid_format in invalid_formats_validation_error:
        with pytest.raises(ValidationError):
            EventSeed(invalid_format)

    # Test invalid ASN format that gets parsed as something else
    event_seed = EventSeed("ASNXYZ")
    assert event_seed.type == "DNS_NAME"  # Falls back to DNS parsing
    assert event_seed.data == "asnxyz"

    # Test valid edge cases
    valid_formats = ["ASN:0", "AS:0", "ASN:4294967295", "AS:4294967295"]
    for valid_format in valid_formats[:2]:  # Test just a couple to avoid huge ASN numbers
        event_seed = EventSeed(valid_format)
        assert event_seed.type == "ASN"

    # Test ASN with no subnets
    from unittest.mock import AsyncMock, MagicMock, patch

    mock_empty_client = MagicMock()
    mock_empty_client.lookup_asn = AsyncMock(return_value=None)
    mock_empty_client.cleanup = AsyncMock()

    target = BBOTTarget(target=["ASN:99999"])  # Non-existent ASN

    initial_seeds = len(target.seeds.event_seeds)
    with patch("asndb.ASNDB", return_value=mock_empty_client):
        scan = bbot_scanner("ASN:99999")
        await target.generate_children(helpers=scan.helpers)

    # Should not add any new seeds for empty ASN
    assert len(target.seeds.event_seeds) == initial_seeds

    # Test that ASN blacklisting would happen after expansion
    # Since ASN targets can't be directly added to blacklist (no host),
    # the proper way would be to expand the ASN and then blacklist the IP ranges
    target = BBOTTarget(target=["evilcorp.com"])
    # This demonstrates the intended usage pattern - add expanded IP ranges to blacklist
    target.blacklist.add("8.8.8.0/24")  # Would come from ASN expansion
    assert "8.8.8.0/24" in target.blacklist.inputs


@pytest.mark.asyncio
async def test_asn_blacklist_functionality(bbot_scanner):
    """Test ASN blacklisting: IP range target with ASN in blacklist should expand and block subnets."""
    from unittest.mock import AsyncMock, MagicMock, patch

    mock_client = MagicMock()
    mock_client.lookup_asn = AsyncMock(
        return_value={
            "asn": 15169,
            "subnets": ["8.8.8.0/24"],
        }
    )
    mock_client.cleanup = AsyncMock()

    with patch("asndb.ASNDB", return_value=mock_client):
        # Target: 8.8.8.0/23 (includes 8.8.8.0/24 and 8.8.9.0/24)
        # Blacklist: ASN:15169 (should expand to 8.8.8.0/24 and block it)
        scan = bbot_scanner("8.8.8.0/23", blacklist=["ASN:15169"])
        await scan._prep()

        # The ASN should have been expanded and the subnet should be in blacklist
        assert "8.8.8.0/24" in scan.preset.target.blacklist.hosts

        # 8.8.8.x should be blocked (ASN subnet in blacklist)
        assert not scan.in_scope("8.8.8.1")
        assert not scan.in_scope("8.8.8.8")
        assert not scan.in_scope("8.8.8.255")

        # 8.8.9.x should be allowed (in target but ASN doesn't cover this)
        assert scan.in_scope("8.8.9.1")
        assert scan.in_scope("8.8.9.8")
        assert scan.in_scope("8.8.9.255")

        # IPs outside the target should not be in scope
        assert not scan.in_scope("8.8.7.1")
        assert not scan.in_scope("8.8.10.1")


@pytest.mark.asyncio
async def test_asn_len_overflow(bbot_scanner):
    """Regression test: len() on targets with many ASN subnets must not overflow.

    RadixTarget.__len__() counts individual IPs, which can exceed sys.maxsize
    for large ASNs (e.g. AS15169 with 1000+ subnets). The scanner log message
    must use len(event_seeds) instead.
    """
    from unittest.mock import AsyncMock, MagicMock, patch

    # Simulate a large ASN with many /16 subnets — total IPs would overflow an index
    many_subnets = [f"10.{i}.0.0/16" for i in range(200)]

    mock_client = MagicMock()
    mock_client.lookup_asn = AsyncMock(return_value={"asn": 99999, "subnets": many_subnets})
    mock_client.cleanup = AsyncMock()

    with patch("asndb.ASNDB", return_value=mock_client):
        scan = bbot_scanner("ASN:99999")
        # _prep() calls generate_children() and then does len(self.seeds.event_seeds)
        # Before the fix, this raised OverflowError from len() on the RadixTarget
        await scan._prep()

        # Verify expansion worked
        assert len(scan.preset.target.seeds.event_seeds) > 200


@pytest.mark.asyncio
async def test_asn_event_json_serialization(bbot_scanner):
    """Regression test: ASN events must serialize and deserialize correctly."""
    from unittest.mock import AsyncMock, MagicMock, patch
    from bbot.core.event.base import event_from_json

    mock_client = MagicMock()
    mock_client.lookup_asn = AsyncMock(return_value={"asn": 12345, "subnets": ["192.0.2.0/24"]})
    mock_client.cleanup = AsyncMock()

    with patch("asndb.ASNDB", return_value=mock_client):
        scan = bbot_scanner("ASN:12345")
        await scan._prep()

        # Create an ASN event like the scanner does (bare int input)
        asn_event = scan.make_event(12345, "ASN", parent=scan.root_event)
        assert asn_event.data == {"asn": 12345}

        # Serialize to JSON
        j = asn_event.json()
        assert j["type"] == "ASN"
        assert j["data_json"] == {"asn": 12345}

        # Round-trip: reconstruct from JSON
        reconstructed = event_from_json(j)
        assert reconstructed.type == "ASN"
        assert reconstructed.data == {"asn": 12345}


@pytest.mark.asyncio
async def test_asn_resolution_failure_aborts_scan(bbot_scanner):
    """When the asndb API is unreachable, the scan should abort gracefully with a helpful message."""
    from unittest.mock import AsyncMock, MagicMock, patch

    from bbot.errors import ScanError

    mock_client = MagicMock()
    mock_client.lookup_asn = AsyncMock(side_effect=Exception("connection refused"))
    mock_client.cleanup = AsyncMock()

    with patch("asndb.ASNDB", return_value=mock_client):
        scan = bbot_scanner("ASN:15169")
        with pytest.raises(ScanError, match="Failed to resolve ASN target"):
            await scan._prep()

    # Should have retried 3 times
    assert mock_client.lookup_asn.call_count == 3


@pytest.mark.asyncio
async def test_asn_resolution_failure_retries(bbot_scanner):
    """ASN resolution should succeed if a retry works after initial failures."""
    from unittest.mock import AsyncMock, MagicMock, patch

    call_count = 0

    async def lookup_asn_side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise Exception("connection refused")
        return {"asn": 15169, "subnets": ["8.8.8.0/24"]}

    mock_client = MagicMock()
    mock_client.lookup_asn = AsyncMock(side_effect=lookup_asn_side_effect)
    mock_client.cleanup = AsyncMock()

    with patch("asndb.ASNDB", return_value=mock_client):
        scan = bbot_scanner("ASN:15169")
        await scan._prep()

        # Should have succeeded on the 3rd attempt
        assert call_count == 3
        assert "8.8.8.0/24" in scan.preset.target.seeds.hosts


@pytest.mark.asyncio
async def test_blacklist_regex(bbot_scanner, bbot_httpserver):
    from bbot.scanner.target import ScanBlacklist

    blacklist = ScanBlacklist("evilcorp.com")
    assert blacklist.inputs == {"evilcorp.com"}
    assert "www.evilcorp.com" in blacklist
    assert "http://www.evilcorp.com" in blacklist
    blacklist.add("RE:test")
    assert "REGEX:test" in blacklist.inputs
    assert set(blacklist.inputs) == {"evilcorp.com", "REGEX:test"}
    assert blacklist.blacklist_regexes
    assert next(iter(blacklist.blacklist_regexes)).pattern == "test"
    result1 = blacklist.get("test.com")
    assert result1 == "test.com"
    result2 = blacklist.get("www.evilcorp.com")
    assert result2 == "evilcorp.com"
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
    assert "http://test.com/asdf/123456.aspx#asdf" in blacklist
    assert "http://test.com/asdf/123456.aspx" in blacklist

    bbot_httpserver.expect_request(uri="/").respond_with_data(
        f"""
        <a href='{HTTPSERVER_URL}/asdfevil333asdf'/>
        <a href='{HTTPSERVER_URL}/logout.aspx'/>
    """
    )
    bbot_httpserver.expect_request(uri="/asdfevilasdf").respond_with_data("")
    bbot_httpserver.expect_request(uri="/logout.aspx").respond_with_data("")

    # make sure URL is detected normally
    scan = bbot_scanner(f"{HTTPSERVER_URL}/", presets=["spider"], config={"excavate": True}, debug=True)
    await scan._prep()
    assert {r.pattern for r in scan.target.blacklist.blacklist_regexes} == {r"/.*(sign|log)[_-]?out"}
    events = [e async for e in scan.async_start()]
    urls = [e.url for e in events if e.type == "URL"]
    assert len(urls) == 2
    assert set(urls) == {f"{HTTPSERVER_URL}/", f"{HTTPSERVER_URL}/asdfevil333asdf"}

    # same scan again but with blacklist regex
    scan = bbot_scanner(
        f"{HTTPSERVER_URL}/",
        blacklist=[r"RE:evil[0-9]{3}"],
        presets=["spider"],
        config={"excavate": True},
        debug=True,
    )
    await scan._prep()
    assert len(scan.target.blacklist) == 2
    assert scan.target.blacklist.blacklist_regexes
    assert {r.pattern for r in scan.target.blacklist.blacklist_regexes} == {
        r"evil[0-9]{3}",
        r"/.*(sign|log)[_-]?out",
    }
    events = [e async for e in scan.async_start()]
    urls = [e.url for e in events if e.type == "URL"]
    assert len(urls) == 1
    assert set(urls) == {f"{HTTPSERVER_URL}/"}


def test_blacklist_get_invalid_host():
    """Blacklist.get() should not crash when _make_event_seed returns None for an invalid host."""
    from bbot.scanner.target import ScanBlacklist

    blacklist = ScanBlacklist("bad.com")
    # Inputs that fail EventSeed validation (e.g. wildcards, single chars) cause
    # _make_event_seed() to return None. Previously this crashed with:
    # AttributeError: 'NoneType' object has no attribute 'host'
    for invalid in ["*", "*.example.com", "a", ""]:
        result = blacklist.get(invalid)
        assert result is None
    # Multi-level subdomains should never crash Blacklist.get(), even if
    # future changes cause EventSeed to reject them
    for hostname in ["cdn.info.test.example.com", "a.b.c.d.example.com", "x.y.example.co.uk"]:
        result = blacklist.get(hostname)
        assert result is None
    # Verify actual blacklisted hosts still work
    result = blacklist.get("bad.com")
    assert result is not None


def test_no_double_parsing():
    """Regression test: when seeds are auto-populated from target, EventSeed parsing
    should happen only once (via ScanTarget), not twice. BBOTTarget should pass
    pre-parsed EventSeed objects to ScanSeeds instead of raw strings."""
    from unittest.mock import patch
    from bbot.scanner.target import BBOTTarget
    from bbot.core.event.helpers import EventSeed as _real_EventSeed

    targets = ["evilcorp.com", "1.2.3.4", "https://example.com", "10.0.0.0/24"]

    call_count = 0
    original_EventSeed = _real_EventSeed

    def counting_EventSeed(input):
        nonlocal call_count
        call_count += 1
        return original_EventSeed(input)

    with patch("bbot.scanner.target.EventSeed", side_effect=counting_EventSeed):
        BBOTTarget(target=targets)

    # EventSeed should be called once per target (for ScanTarget), not twice
    assert call_count == len(targets), (
        f"EventSeed was called {call_count} times for {len(targets)} targets; "
        f"expected {len(targets)} (seeds should reuse pre-parsed EventSeed objects)"
    )


def test_target_comments():
    """Target strings support # comments — both full-line and inline."""
    from bbot.scanner.target import BBOTTarget

    target = BBOTTarget(
        target=[
            "# this is a full-line comment",
            "evilcorp.com # main evilcorp domain",
            "  # indented comment  ",
            "1.2.3.0/24 # internal network",
            "othercorp.com",
        ],
    )

    # comment-only lines are ignored
    assert len(target.target) == 3

    # inline comments are stripped — targets work normally
    assert target.in_target("evilcorp.com")
    assert target.in_target("www.evilcorp.com")
    assert target.in_target("1.2.3.4")
    assert target.in_target("othercorp.com")

    # the comment text itself is not a target
    assert not target.in_target("main")
    assert not target.in_target("internal")


def test_target_comments_url_fragment_not_stripped():
    """A # inside a URL (fragment) must NOT be treated as a comment.

    BBOT's URL normalisation may drop fragments, but the important thing
    is that the host is still recognised as a valid target.
    """
    from bbot.scanner.target import BBOTTarget

    target = BBOTTarget(target=["http://evilcorp.com/page#section"])
    assert target.in_target("evilcorp.com")
    assert len(target.target) == 1


def test_target_comments_blacklist():
    """Comments work for blacklist entries too."""
    from bbot.scanner.target import BBOTTarget

    target = BBOTTarget(
        target=["evilcorp.com"],
        blacklist=[
            "# don't scan the blog",
            "blog.evilcorp.com # unstable host",
        ],
    )
    assert target.in_scope("www.evilcorp.com")
    assert not target.in_scope("blog.evilcorp.com")
    assert len(target.blacklist) == 1


def test_target_comments_seeds():
    """Comments work for seed entries too."""
    from bbot.scanner.target import BBOTTarget

    target = BBOTTarget(
        target=["evilcorp.com"],
        seeds=[
            "# seed comment",
            "evilcorp.com # the main domain",
        ],
    )
    assert "evilcorp.com" in target.seeds
    assert len(target.seeds) == 1


def test_target_comments_from_file(tmp_path):
    """Comments in a target file are stripped when loaded via chain_lists."""
    from bbot.core.helpers.misc import chain_lists

    target_file = tmp_path / "targets.txt"
    target_file.write_text(
        "# My target list\n"
        "evilcorp.com # main domain\n"
        "\n"
        "  # another comment\n"
        "othercorp.com\n"
        "192.168.1.0/24 # lab network\n"
        "http://example.com/page#fragment # with a URL fragment\n"
    )

    result = chain_lists([str(target_file)], try_files=True, _strip_comments=True)
    assert "evilcorp.com" in result
    assert "othercorp.com" in result
    assert "192.168.1.0/24" in result
    assert "http://example.com/page#fragment" in result
    # comments and blank lines are gone
    assert not any(r.lstrip().startswith("#") for r in result)
    assert len(result) == 4


def test_strip_comments_helper():
    """Unit tests for the strip_comments function."""
    from bbot.core.helpers.misc import strip_comments

    # full-line comments
    assert strip_comments("# comment") == ""
    assert strip_comments("  # indented comment") == ""

    # inline comments
    assert strip_comments("evilcorp.com # main domain") == "evilcorp.com"
    assert strip_comments("1.2.3.0/24\t# tab comment") == "1.2.3.0/24"

    # no comment
    assert strip_comments("evilcorp.com") == "evilcorp.com"

    # URL fragment (no space before #) is preserved
    assert strip_comments("http://example.com/page#section") == "http://example.com/page#section"

    # URL fragment with trailing inline comment
    assert strip_comments("http://example.com/page#section # a comment") == "http://example.com/page#section"

    # empty / whitespace
    assert strip_comments("") == ""
    assert strip_comments("   ") == "   "
