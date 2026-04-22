from ..bbot_fixtures import *

from bbot.core.helpers.dns.helpers import all_rdtypes, common_srvs, extract_targets, record_to_text, service_record


# Common mock dataset (zone-file format -- TXT character-strings must be quoted
# to keep whitespace inside the payload from being tokenized).
mock_records = {
    "one.one.one.one": {
        "A": ["1.1.1.1", "1.0.0.1"],
        "AAAA": ["2606:4700:4700::1111", "2606:4700:4700::1001"],
        "TXT": [
            '"v=spf1 ip4:103.151.192.0/23 ip4:185.12.80.0/22 ip4:188.172.128.0/20 ip4:192.161.144.0/20 ip4:216.198.0.0/18 ~all"'
        ],
    },
    "1.1.1.1.in-addr.arpa": {"PTR": ["one.one.one.one."]},
}


@pytest.mark.asyncio
async def test_dns_helper(bbot_scanner):
    scan = bbot_scanner()
    await scan.helpers.dns._mock_dns({"asdf.example.com": {"A": ["1.2.3.4"]}})
    result = await scan.helpers.dns.resolve("asdf.example.com")
    assert "1.2.3.4" in result


@pytest.mark.asyncio
async def test_dns_engine(bbot_scanner):
    """High-level resolve / batch / null-MX cleaning via scan.helpers.dns."""
    scan = bbot_scanner()
    await scan._prep()
    await scan.helpers.dns._mock_dns(
        {
            "one.one.one.one": {"A": ["1.1.1.1"]},
            "1.1.1.1.in-addr.arpa": {"PTR": ["one.one.one.one"]},
        }
    )

    # forward resolve
    result = await scan.helpers.dns.resolve("one.one.one.one")
    assert "1.1.1.1" in result
    # we only mocked A, not AAAA
    assert "2606:4700:4700::1111" not in result

    # reverse resolve
    result = await scan.helpers.dns.resolve("1.1.1.1", "PTR")
    assert "one.one.one.one" in result

    # batch resolution -- many hosts, single rdtype
    await scan.helpers.dns._mock_dns(
        {
            "one.one.one.one": {"A": ["1.1.1.1"]},
            "two.two.two.two": {"A": ["2.2.2.2"]},
        }
    )
    batch_results = {}
    async for host, response in scan.helpers.dns.resolve_batch_full(["one.one.one.one", "two.two.two.two"], "A"):
        addrs = {ans.rdata["A"] for ans in response.response.answers}
        batch_results[host] = addrs
    assert batch_results["one.one.one.one"] == {"1.1.1.1"}
    assert batch_results["two.two.two.two"] == {"2.2.2.2"}

    # null MX (RFC 7505: "0 .") must produce no extracted targets
    await scan.helpers.dns._mock_dns({"evilcorp.com": {"MX": ["0 ."]}})
    mx_response = await scan.helpers.dns.resolve_full("evilcorp.com", "MX")
    extracted = set()
    for ans in mx_response.response.answers:
        extracted.update(extract_targets(ans))
    assert not extracted


@pytest.mark.asyncio
async def test_dns_resolution(bbot_scanner):
    """Multi-rdtype resolution + SPF affiliate tagging end-to-end."""
    scan = bbot_scanner()
    await scan._prep()
    await scan.helpers.dns._mock_dns(
        {
            "one.one.one.one": {
                "A": ["1.1.1.1", "1.0.0.1"],
                "AAAA": ["2606:4700:4700::1111", "2606:4700:4700::1001"],
                "TXT": ['"v=spf1 ip4:1.2.3.4 ~all"'],
            },
            "evilcorp.com": {
                "NS": ["ns1.evilcorp.com.", "ns2.evilcorp.com."],
                "SOA": ["ns1.evilcorp.com. admin.evilcorp.com. 1 7200 3600 1209600 3600"],
                "MX": ["10 mail.evilcorp.com."],
            },
        }
    )

    # mixed-rdtype lookups
    a = await scan.helpers.dns.resolve("one.one.one.one", "A")
    assert {"1.1.1.1", "1.0.0.1"}.issubset(a)
    aaaa = await scan.helpers.dns.resolve("one.one.one.one", "AAAA")
    assert "2606:4700:4700::1111" in aaaa
    for rdtype in ("NS", "SOA", "MX"):
        results = await scan.helpers.dns.resolve("evilcorp.com", rdtype)
        assert results, f"no results for {rdtype}"

    # full SPF -> affiliate flow: TXT on evilcorp.com mentions cloudprovider.com,
    # which should be emitted as a DNS_NAME tagged "affiliate"
    scan2 = bbot_scanner("evilcorp.com", config={"dns": {"minimal": False}})
    await scan2._prep()
    await scan2.helpers.dns._mock_dns(
        {
            "evilcorp.com": {"TXT": ['"v=spf1 include:cloudprovider.com ~all"']},
            "cloudprovider.com": {"A": ["1.2.3.4"]},
        }
    )
    events = [e async for e in scan2.async_start()]
    affiliates = [
        e for e in events if e.type == "DNS_NAME" and e.data == "cloudprovider.com" and "affiliate" in e.tags
    ]
    assert len(affiliates) == 1

    await scan._cleanup()
    await scan2._cleanup()


@pytest.mark.asyncio
async def test_resolve_full_and_extract(bbot_scanner):
    """resolve_full + extract_targets + record_to_text on the new blastdns Records."""
    scan = bbot_scanner()
    await scan.helpers.dns._mock_dns(
        {
            "one.one.one.one": {
                "A": ["1.1.1.1"],
                "AAAA": ["2606:4700:4700::1111"],
                "MX": ["10 mail.one.one.one.one."],
            },
        }
    )

    a_response = await scan.helpers.dns.resolve_full("one.one.one.one", "A")
    a_targets = set()
    for ans in a_response.response.answers:
        a_targets.update(extract_targets(ans))
    assert ("A", "1.1.1.1") in a_targets

    mx_response = await scan.helpers.dns.resolve_full("one.one.one.one", "MX")
    mx_targets = set()
    for ans in mx_response.response.answers:
        mx_targets.update(extract_targets(ans))
        # the MX record_to_text matches dnspython's "preference exchange" format
        assert record_to_text(ans).endswith("mail.one.one.one.one.")
    assert ("MX", "mail.one.one.one.one") in mx_targets


@pytest.mark.asyncio
async def test_resolve_multi_full(bbot_scanner):
    """resolve_multi_full does many rdtypes for one host in a single Rust call."""
    scan = bbot_scanner()
    await scan.helpers.dns._mock_dns(
        {
            "one.one.one.one": {
                "A": ["1.1.1.1"],
                "AAAA": ["2606:4700:4700::1111"],
            },
        }
    )

    results = await scan.helpers.dns.resolve_multi_full("one.one.one.one", ["A", "AAAA"])
    assert "A" in results and "AAAA" in results
    a_addrs = {ans.rdata["A"] for ans in results["A"].response.answers}
    aaaa_addrs = {ans.rdata["AAAA"] for ans in results["AAAA"].response.answers}
    assert "1.1.1.1" in a_addrs
    assert "2606:4700:4700::1111" in aaaa_addrs


@pytest.mark.asyncio
async def test_resolve_event(bbot_scanner):
    """end-to-end: dnsresolve uses resolve_multi_full and populates raw_dns_records."""
    scan = bbot_scanner("one.one.one.one", "1.1.1.1", config={"dns": {"minimal": False}})
    await scan._prep()
    await scan.helpers.dns._mock_dns(mock_records)

    resolved_event = scan.make_event("one.one.one.one", "DNS_NAME", parent=scan.root_event)
    url_event = scan.make_event("http://one.one.one.one/", "URL_UNVERIFIED", parent=scan.root_event)
    dnsresolve = scan.modules["dnsresolve"]
    await dnsresolve.handle_event(resolved_event)
    await dnsresolve.handle_event(url_event)

    assert "1.1.1.1" in url_event.resolved_hosts
    # URL events don't get dns_children populated
    assert not url_event.dns_children
    assert resolved_event.resolved_hosts == url_event.resolved_hosts
    # DNS_NAME events do
    assert "1.1.1.1" in resolved_event.dns_children["A"]
    assert "A" in resolved_event.raw_dns_records
    assert "AAAA" in resolved_event.raw_dns_records
    assert "a-record" in resolved_event.tags
    assert "a-record" not in url_event.tags

    await scan._cleanup()


@pytest.mark.asyncio
async def test_dns_raw_records(bbot_scanner):
    """RAW_DNS_RECORD events carry the decoded text representation (no dnspython-style quoting)."""
    from bbot.modules.base import BaseModule

    expected_txt = (
        "v=spf1 ip4:103.151.192.0/23 ip4:185.12.80.0/22 "
        "ip4:188.172.128.0/20 ip4:192.161.144.0/20 ip4:216.198.0.0/18 ~all"
    )

    class DummyModule(BaseModule):
        watched_events = ["*"]

        async def setup(self):
            self.events = []
            return True

        async def handle_event(self, event):
            self.events.append(event)

    # scan without omitted event type -- raw record should both flow through and reach output
    scan = bbot_scanner("one.one.one.one", "1.1.1.1", config={"dns": {"minimal": False}, "omit_event_types": []})
    await scan._prep()
    await scan.helpers.dns._mock_dns(mock_records)
    dummy_module = DummyModule(scan)
    await dummy_module.setup()
    scan.modules["dummy_module"] = dummy_module
    events = [e async for e in scan.async_start()]
    raw_records = [e for e in events if e.type == "RAW_DNS_RECORD"]
    assert len(raw_records) == 1
    rec = raw_records[0]
    assert rec.host == "one.one.one.one"
    assert rec.data["host"] == "one.one.one.one"
    assert rec.data["type"] == "TXT"
    assert rec.data["answer"] == expected_txt
    assert rec.discovery_context == "TXT lookup on one.one.one.one produced RAW_DNS_RECORD"

    # scan with omitted event type -- no raw records anywhere
    scan = bbot_scanner("one.one.one.one", config={"dns": {"minimal": False}, "omit_event_types": ["RAW_DNS_RECORD"]})
    await scan._prep()
    await scan.helpers.dns._mock_dns(mock_records)
    dummy_module = DummyModule(scan)
    await dummy_module.setup()
    scan.modules["dummy_module"] = dummy_module
    events = [e async for e in scan.async_start()]
    assert 0 == len([e for e in events if e.type == "RAW_DNS_RECORD"])
    assert 0 == len([e for e in dummy_module.events if e.type == "RAW_DNS_RECORD"])

    # scan with watching module -- raw records reach the module but aren't output
    DummyModule.watched_events = ["RAW_DNS_RECORD"]
    scan = bbot_scanner("one.one.one.one", config={"dns": {"minimal": False}, "omit_event_types": ["RAW_DNS_RECORD"]})
    await scan._prep()
    await scan.helpers.dns._mock_dns(mock_records)
    dummy_module = DummyModule(scan)
    await dummy_module.setup()
    scan.modules["dummy_module"] = dummy_module
    events = [e async for e in scan.async_start()]
    assert 0 == len([e for e in events if e.type == "RAW_DNS_RECORD"])
    raw_records = [e for e in dummy_module.events if e.type == "RAW_DNS_RECORD"]
    assert len(raw_records) == 1
    assert raw_records[0].data["answer"] == expected_txt


@pytest.mark.asyncio
async def test_wildcards(bbot_scanner):
    """is_wildcard / is_wildcard_domain against a mocked wildcard zone.

    blastdns MockClient supports ``regex:`` prefixed hosts for pattern matching,
    which is how we simulate "every random subdomain resolves to the wildcard".
    """
    # The test config preloads wildcard_ignore with several common domains (incl. evilcorp.com)
    # so override it here to actually exercise wildcard detection.
    scan = bbot_scanner("evilcorp.com", config={"dns": {"wildcard_ignore": []}})
    await scan._prep()
    helpers = scan.helpers

    # *.test.evilcorp.com is a wildcard pointing at 127.0.0.99 (A) and dead::beef (AAAA)
    mock_data = {
        "evilcorp.com": {"A": ["127.0.0.1"]},
        "test.evilcorp.com": {"A": ["127.0.0.99"]},
        r"regex:.*\.test\.evilcorp\.com$": {"A": ["127.0.0.99"], "AAAA": ["dead::beef"]},
    }
    await scan.helpers.dns._mock_dns(mock_data)

    # is_wildcard_domain reports the wildcard pool per parent
    wildcard_domains = await scan.helpers.dns.is_wildcard_domain("asdf.test.evilcorp.com", ["A", "AAAA"])
    assert "test.evilcorp.com" in wildcard_domains
    assert "A" in wildcard_domains["test.evilcorp.com"]
    # the per-zone cache stored both rdtypes for this parent
    assert hash(("test.evilcorp.com", "A")) in scan.helpers.dns._wildcard_cache
    assert hash(("test.evilcorp.com", "AAAA")) in scan.helpers.dns._wildcard_cache
    # the cached wildcard pool contains valid IPs
    cached_a, cached_a_raw = scan.helpers.dns._wildcard_cache[hash(("test.evilcorp.com", "A"))]
    assert cached_a and all(helpers.is_ip(ip) for ip in cached_a)

    # is_wildcard tells us whether a specific hostname is a wildcard hit
    for sub in ("asdf.test.evilcorp.com", "qwer.zxcv.test.evilcorp.com"):
        wildcard_rdtypes = await scan.helpers.dns.is_wildcard(sub, ["A", "AAAA"])
        assert wildcard_rdtypes.get("A") == (True, "test.evilcorp.com")
        assert wildcard_rdtypes.get("AAAA") == (True, "test.evilcorp.com")

    # a bare domain is short-circuited to {}
    non_wildcard = await scan.helpers.dns.is_wildcard("evilcorp.com", ["A"])
    assert non_wildcard == {}

    await scan._cleanup()

    ### wildcard TXT record (empty TXT for any *.test.evilcorp.com) ###

    txt_mock_data = {
        "evilcorp.com": {"A": ["127.0.0.1"]},
        "test.evilcorp.com": {"A": ["127.0.0.2"]},
        "www.test.evilcorp.com": {"AAAA": ["dead::beef"]},
        # any subdomain of test.evilcorp.com gets an empty TXT (a known wildcard pattern)
        r"regex:.*\.test\.evilcorp\.com$": {"TXT": [""]},
    }

    # first, run with wildcard detection disabled for evilcorp.com
    scan = bbot_scanner(
        "evilcorp.com",
        seeds=["bbot.fdsa.www.test.evilcorp.com"],
        config={
            "dns": {"minimal": False, "search_distance": 5, "wildcard_ignore": ["evilcorp.com"]},
            "speculate": True,
        },
    )
    await scan._prep()
    await scan.helpers.dns._mock_dns(txt_mock_data)
    events = [e async for e in scan.async_start()]
    dns_names = sorted(e.data for e in events if e.type == "DNS_NAME")
    assert dns_names == [
        "bbot.fdsa.www.test.evilcorp.com",
        "evilcorp.com",
        "fdsa.www.test.evilcorp.com",
        "test.evilcorp.com",
        "www.test.evilcorp.com",
    ]
    dns_names_by_host = {e.host: e for e in events if e.type == "DNS_NAME"}
    # nothing should be tagged wildcard since detection is disabled for evilcorp.com
    for e in dns_names_by_host.values():
        assert "wildcard" not in e.tags
        assert not any(t.endswith("-wildcard") for t in e.tags)
    assert dns_names_by_host["evilcorp.com"].resolved_hosts == {"127.0.0.1"}
    assert dns_names_by_host["test.evilcorp.com"].resolved_hosts == {"127.0.0.2"}
    assert dns_names_by_host["www.test.evilcorp.com"].resolved_hosts == {"dead::beef"}

    # then run with wildcard detection enabled
    scan = bbot_scanner(
        "evilcorp.com",
        seeds=["bbot.fdsa.www.test.evilcorp.com"],
        config={
            "dns": {"minimal": False, "search_distance": 5, "wildcard_ignore": []},
            "speculate": True,
        },
    )
    await scan._prep()
    await scan.helpers.dns._mock_dns(txt_mock_data)
    events = [e async for e in scan.async_start()]
    dns_names_by_host = {e.host: e for e in events if e.type == "DNS_NAME"}

    # the seed event keeps its real host (renaming is suppressed for seeds)
    assert "bbot.fdsa.www.test.evilcorp.com" in dns_names_by_host
    # at least one wildcard-renamed event was emitted
    renamed = [e for e in events if e.type == "DNS_NAME" and e.data.startswith("_wildcard.")]
    assert renamed, "expected at least one _wildcard.* renamed event"
    # explicit www.test.evilcorp.com still has its real AAAA, but is tagged wildcard for TXT
    if "www.test.evilcorp.com" in dns_names_by_host:
        assert "txt-wildcard" in dns_names_by_host["www.test.evilcorp.com"].tags
        assert dns_names_by_host["www.test.evilcorp.com"].resolved_hosts == {"dead::beef"}

    ### runaway SRV wildcard ###

    # mock a chain of SRV records that recursively point to a deeper subdomain.
    # without runaway detection, this would generate infinite events.
    runaway_mock = {
        "evilcorp.com": {"A": ["127.0.0.1"], "SRV": ["0 100 389 test.evilcorp.com."]},
        "test.evilcorp.com": {"AAAA": ["dead::beef"], "SRV": ["0 100 389 test.test.evilcorp.com."]},
        "test.test.evilcorp.com": {"SRV": ["0 100 389 test.test.test.evilcorp.com."]},
        "test.test.test.evilcorp.com": {"SRV": ["0 100 389 test.test.test.test.evilcorp.com."]},
        "test.test.test.test.evilcorp.com": {"SRV": ["0 100 389 test.test.test.test.test.evilcorp.com."]},
    }
    scan = bbot_scanner(
        "evilcorp.com",
        config={
            "dns": {
                "minimal": False,
                "search_distance": 5,
                "wildcard_ignore": [],
                "runaway_limit": 3,
            },
        },
    )
    await scan._prep()
    await scan.helpers.dns._mock_dns(runaway_mock)
    events = [e async for e in scan.async_start()]
    dns_name_data = sorted(e.data for e in events if e.type == "DNS_NAME")
    # runaway_limit=3 should stop the cascade before the 5th level
    assert "test.test.test.test.test.evilcorp.com" not in dns_name_data
    # the leaf event that hit the runaway limit should be tagged accordingly
    runaway_tagged = [e for e in events if e.type == "DNS_NAME" and any(t.startswith("runaway-dns-") for t in e.tags)]
    assert runaway_tagged, "expected at least one event tagged runaway-dns-N"

    await scan._cleanup()

    ### dns_resolve_distance bookkeeping ###

    scan = bbot_scanner("1.1.1.1")
    await scan._prep()
    dnsresolve = scan.modules["dnsresolve"]

    event_distance_0 = scan.make_event("8.8.8.8", module=dnsresolve._make_dummy_module("PTR"), parent=scan.root_event)
    assert event_distance_0.dns_resolve_distance == 0
    event_distance_1 = scan.make_event(
        "evilcorp.com", module=dnsresolve._make_dummy_module("A"), parent=event_distance_0
    )
    assert event_distance_1.dns_resolve_distance == 1
    event_distance_2 = scan.make_event("1.2.3.4", module=dnsresolve._make_dummy_module("PTR"), parent=event_distance_1)
    # IP_ADDRESS inherits its parent's distance directly
    assert event_distance_2.dns_resolve_distance == 1
    event_distance_3 = scan.make_event(
        "evilcorp.org", module=dnsresolve._make_dummy_module("A"), parent=event_distance_2
    )
    assert event_distance_3.dns_resolve_distance == 2

    await scan._cleanup()


@pytest.mark.asyncio
async def test_wildcard_deduplication(bbot_scanner):
    """A module emitting many wildcard subdomains should produce only one _wildcard.* event."""
    from bbot.modules.base import BaseModule

    class DummyModule(BaseModule):
        watched_events = ["DNS_NAME"]
        per_domain_only = True

        async def handle_event(self, event):
            for i in range(30):
                await self.emit_event(f"www{i}.evilcorp.com", "DNS_NAME", parent=event)

    # *.evilcorp.com returns an empty TXT record (a known wildcard pattern that
    # would normally cause every subdomain to look distinct). With wildcard
    # detection enabled, dnsresolve should fold them all into _wildcard.evilcorp.com.
    mock_data = {
        "evilcorp.com": {"A": ["127.0.0.1"]},
        r"regex:.*\.evilcorp\.com$": {"TXT": [""]},
    }

    scan = bbot_scanner(
        "evilcorp.com",
        config={"dns": {"minimal": False, "wildcard_ignore": []}, "omit_event_types": []},
    )
    await scan._prep()
    await scan.helpers.dns._mock_dns(mock_data)
    dummy_module = DummyModule(scan)
    scan.modules["dummy_module"] = dummy_module
    events = [e async for e in scan.async_start()]

    dns_name_events = [e for e in events if e.type == "DNS_NAME"]
    # exactly one _wildcard.evilcorp.com event despite 30 emissions
    wildcard_events = [e for e in dns_name_events if e.data == "_wildcard.evilcorp.com"]
    assert len(wildcard_events) == 1
    # the only DNS_NAMEs should be evilcorp.com itself + the dedup'd wildcard
    assert sorted(e.data for e in dns_name_events) == ["_wildcard.evilcorp.com", "evilcorp.com"]


@pytest.mark.asyncio
async def test_dns_graph_structure(bbot_scanner):
    scan = bbot_scanner("https://evilcorp.com", config={"dns": {"search_distance": 1, "minimal": False}})
    await scan._prep()
    await scan.helpers.dns._mock_dns(
        {
            "evilcorp.com": {"CNAME": ["www.evilcorp.com"]},
            "www.evilcorp.com": {"CNAME": ["test.evilcorp.com"]},
            "test.evilcorp.com": {"A": ["127.0.0.1"]},
        }
    )
    events = [e async for e in scan.async_start()]
    assert len(events) == 6
    non_scan_events = [e for e in events if e.type != "SCAN"]
    assert sorted([e.type for e in non_scan_events]) == ["DNS_NAME", "DNS_NAME", "DNS_NAME", "URL_UNVERIFIED"]
    events_by_data = {e.pretty_string: e for e in non_scan_events}
    assert set(events_by_data) == {"https://evilcorp.com/", "evilcorp.com", "www.evilcorp.com", "test.evilcorp.com"}
    assert events_by_data["test.evilcorp.com"].parent.data == "www.evilcorp.com"
    assert str(events_by_data["test.evilcorp.com"].module) == "CNAME"
    assert events_by_data["www.evilcorp.com"].parent.data == "evilcorp.com"
    assert str(events_by_data["www.evilcorp.com"].module) == "CNAME"
    assert events_by_data["evilcorp.com"].parent.url == "https://evilcorp.com/"
    assert str(events_by_data["evilcorp.com"].module) == "host"


@pytest.mark.asyncio
async def test_hostname_extraction(bbot_scanner):
    scan = bbot_scanner("evilcorp.com", config={"dns": {"minimal": False}})
    await scan._prep()
    await scan.helpers.dns._mock_dns(
        {
            "evilcorp.com": {
                "A": ["127.0.0.1"],
                "TXT": [
                    '"v=spf1 include:spf-a.evilcorp.com include:spf-b.evilcorp.com include:icpbounce.com '
                    "include:shops.shopify.com include:_spf.qemailserver.com include:spf.mandrillapp.com "
                    'include:spf.protection.office365.us include:spf-003ea501.gpphosted.com 127.0.0.1 -all"'
                ],
            }
        }
    )
    events = [e async for e in scan.async_start()]
    dns_name_events = [e for e in events if e.type == "DNS_NAME"]
    main_dns_event = [e for e in dns_name_events if e.data == "evilcorp.com"]
    assert len(main_dns_event) == 1
    main_dns_event = main_dns_event[0]
    dns_children = main_dns_event.dns_children
    assert dns_children["A"] == {"127.0.0.1"}
    assert dns_children["TXT"] == {
        "spf-a.evilcorp.com",
        "spf-b.evilcorp.com",
        "icpbounce.com",
        "shops.shopify.com",
        "_spf.qemailserver.com",
        "spf.mandrillapp.com",
        "spf.protection.office365.us",
        "spf-003ea501.gpphosted.com",
        "127.0.0.1",
    }


@pytest.mark.asyncio
async def test_dns_helpers(bbot_scanner):
    assert service_record("") is False
    assert service_record("localhost") is False
    assert service_record("www.example.com") is False
    assert service_record("www.example.com", "SRV") is True
    assert service_record("_custom._service.example.com", "SRV") is True
    assert service_record("_custom._service.example.com", "A") is False
    # top 100 most common SRV records
    for srv_record in common_srvs[:100]:
        hostname = f"{srv_record}.example.com"
        assert service_record(hostname) is True

    # all_rdtypes is the canonical list -- make sure it's not empty and contains the basics
    assert "A" in all_rdtypes and "AAAA" in all_rdtypes and "CNAME" in all_rdtypes

    # make sure system nameservers are excluded from use by DNS brute force
    brute_nameservers = tempwordlist(["1.2.3.4", "8.8.4.4", "4.3.2.1", "8.8.8.8"])
    scan = bbot_scanner(config={"dns": {"brute_nameservers": brute_nameservers}})
    await scan._prep()
    scan.helpers.dns.system_resolvers = ["8.8.8.8", "8.8.4.4"]
    resolver_file = await scan.helpers.dns.brute.resolver_file()
    resolvers = set(scan.helpers.read_file(resolver_file))
    assert resolvers == {"1.2.3.4", "4.3.2.1"}
