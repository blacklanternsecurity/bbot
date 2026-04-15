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

    # is_wildcard tells us whether a specific hostname is a wildcard hit
    wildcard_rdtypes = await scan.helpers.dns.is_wildcard("asdf.test.evilcorp.com", ["A", "AAAA"])
    assert wildcard_rdtypes.get("A") == (True, "test.evilcorp.com")

    # a non-wildcard sibling is not flagged
    non_wildcard = await scan.helpers.dns.is_wildcard("evilcorp.com", ["A"])
    # is_domain short-circuits to {} for the bare domain
    assert non_wildcard == {}

    await scan._cleanup()


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
