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
async def test_extract_targets_spf_ips(bbot_scanner):
    """SPF TXT records: extract IPs and CIDRs (ip4:/ip6:) alongside hostnames."""
    scan = bbot_scanner()
    await scan._prep()
    await scan.helpers.dns._mock_dns(
        {
            "evilcorp.com": {
                "TXT": [
                    '"v=spf1 ip4:1.2.3.4 ip4:5.6.7.0/24 ip6:2001:db8::/48 include:cloudprovider.com exists:%{i}.sniff.evilcorp.com -all"'
                ],
            },
            "nospf.evilcorp.com": {
                "TXT": ['"google-site-verification=abc123 contact admin.evilcorp.com ip4:9.9.9.0/24"'],
            },
        }
    )
    response = await scan.helpers.dns.resolve_full("evilcorp.com", "TXT")
    extracted = set()
    for ans in response.response.answers:
        extracted.update(extract_targets(ans))
    hosts = {host for _, host in extracted}
    assert "1.2.3.4" in hosts, "single IPv4 from ip4: mechanism not extracted"
    assert "5.6.7.0/24" in hosts, "IPv4 CIDR from ip4: mechanism not extracted"
    assert "2001:db8::/48" in hosts, "IPv6 CIDR from ip6: mechanism not extracted"
    assert {"cloudprovider.com"} <= hosts, "include: hostname not extracted"
    assert "5.6.7.0" not in hosts, "bare network address must not be emitted alongside its CIDR"
    assert not any("sniff" in host or "%" in host for host in hosts), "SPF macro mechanisms must be skipped"

    # non-SPF TXT records are not eligible for IP/CIDR extraction, only hostnames
    response = await scan.helpers.dns.resolve_full("nospf.evilcorp.com", "TXT")
    extracted = set()
    for ans in response.response.answers:
        extracted.update(extract_targets(ans))
    hosts = {host for _, host in extracted}
    assert {"admin.evilcorp.com"} <= hosts, "hostname extraction from non-SPF TXT must be preserved"
    assert "9.9.9.0/24" not in hosts, "CIDR extraction must be gated on v=spf1"


@pytest.mark.asyncio
async def test_extract_targets_spf_ips_end_to_end(bbot_scanner):
    """SPF TXT record all the way through the scan: IPs/CIDRs emitted as IP_ADDRESS / IP_RANGE events."""
    scan = bbot_scanner("evilcorp.com", config={"dns": {"minimal": False}, "scope": {"report_distance": 1}})
    await scan._prep()
    await scan.helpers.dns._mock_dns(
        {
            "evilcorp.com": {
                "TXT": [
                    '"v=spf1 ip4:1.2.3.4 ip4:5.6.7.0/24 ip6:2001:db8::/48 include:cloudprovider.com exists:%{i}.sniff.evilcorp.com -all"'
                ],
            },
            "cloudprovider.com": {"A": ["4.3.2.1"]},
        }
    )
    events = [e async for e in scan.async_start()]
    ip_addresses = {e.data for e in events if e.type == "IP_ADDRESS"}
    ip_ranges = {e.data for e in events if e.type == "IP_RANGE"}
    dns_names = {e.data for e in events if e.type == "DNS_NAME"}
    assert "1.2.3.4" in ip_addresses, "SPF ip4: address was not emitted as an IP_ADDRESS event"
    assert "5.6.7.0/24" in ip_ranges, "SPF ip4: CIDR was not emitted as an IP_RANGE event"
    assert "2001:db8::/48" in ip_ranges, "SPF ip6: CIDR was not emitted as an IP_RANGE event"
    assert {"cloudprovider.com"} <= dns_names, "SPF include: hostname was not emitted as a DNS_NAME event"
    assert not any("sniff" in str(e.data) for e in events if e.type in ("DNS_NAME", "IP_ADDRESS", "IP_RANGE")), (
        "SPF macro mechanism must not produce DNS_NAME/IP events"
    )
    await scan._cleanup()


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

    ### wildcard TXT record (empty TXT for any host ending in test.evilcorp.com) ###

    # regex matches both test.evilcorp.com itself and any subdomain beneath it,
    # mirroring the original custom_lookup_fn's ``query.strip(".").endswith(...)``
    txt_mock_data = {
        "evilcorp.com": {"A": ["127.0.0.1"]},
        "test.evilcorp.com": {"A": ["127.0.0.2"]},
        "www.test.evilcorp.com": {"AAAA": ["dead::beef"]},
        r"regex:^(.+\.)?test\.evilcorp\.com$": {"TXT": [""]},
    }

    # first, run with wildcard detection disabled for evilcorp.com
    scan = bbot_scanner(
        "evilcorp.com",
        seeds=["bbot.fdsa.www.test.evilcorp.com"],
        config={
            "dns": {"minimal": False, "disable": False, "search_distance": 5, "wildcard_ignore": ["evilcorp.com"]},
            "speculate": True,
        },
    )
    await scan._prep()
    await scan.helpers.dns._mock_dns(txt_mock_data)
    events = [e async for e in scan.async_start()]

    assert len(events) == 12
    assert len([e for e in events if e.type == "DNS_NAME"]) == 5
    assert len([e for e in events if e.type == "RAW_DNS_RECORD"]) == 4
    assert sorted([e.data for e in events if e.type == "DNS_NAME"]) == [
        "bbot.fdsa.www.test.evilcorp.com",
        "evilcorp.com",
        "fdsa.www.test.evilcorp.com",
        "test.evilcorp.com",
        "www.test.evilcorp.com",
    ]

    dns_names_by_host = {e.host: e for e in events if e.type == "DNS_NAME"}
    assert dns_names_by_host["evilcorp.com"].tags == {
        "domain",
        "private-ip",
        "in-scope",
        "a-record",
    }
    assert dns_names_by_host["evilcorp.com"].resolved_hosts == {"127.0.0.1"}
    assert dns_names_by_host["test.evilcorp.com"].tags == {
        "subdomain",
        "private-ip",
        "in-scope",
        "a-record",
        "txt-record",
    }
    assert dns_names_by_host["test.evilcorp.com"].resolved_hosts == {"127.0.0.2"}
    assert dns_names_by_host["www.test.evilcorp.com"].tags == {"subdomain", "in-scope", "aaaa-record", "txt-record"}
    assert dns_names_by_host["www.test.evilcorp.com"].resolved_hosts == {"dead::beef"}
    assert dns_names_by_host["fdsa.www.test.evilcorp.com"].tags == {"subdomain", "in-scope", "txt-record"}
    assert dns_names_by_host["fdsa.www.test.evilcorp.com"].resolved_hosts == set()
    assert dns_names_by_host["bbot.fdsa.www.test.evilcorp.com"].tags == {
        "target",
        "subdomain",
        "in-scope",
        "txt-record",
        "seed",
    }
    assert dns_names_by_host["bbot.fdsa.www.test.evilcorp.com"].resolved_hosts == set()

    raw_records_by_host = {e.host: e for e in events if e.type == "RAW_DNS_RECORD"}
    assert raw_records_by_host["test.evilcorp.com"].tags == {"subdomain", "in-scope", "txt-record"}
    assert raw_records_by_host["test.evilcorp.com"].resolved_hosts == {"127.0.0.2"}
    assert raw_records_by_host["www.test.evilcorp.com"].tags == {"subdomain", "in-scope", "txt-record"}
    assert raw_records_by_host["www.test.evilcorp.com"].resolved_hosts == {"dead::beef"}
    assert raw_records_by_host["fdsa.www.test.evilcorp.com"].tags == {"subdomain", "in-scope", "txt-record"}
    assert raw_records_by_host["fdsa.www.test.evilcorp.com"].resolved_hosts == set()
    assert raw_records_by_host["bbot.fdsa.www.test.evilcorp.com"].tags == {"subdomain", "in-scope", "txt-record"}
    assert raw_records_by_host["bbot.fdsa.www.test.evilcorp.com"].resolved_hosts == set()

    # then we run it again with wildcard detection enabled

    scan = bbot_scanner(
        "evilcorp.com",
        seeds=["bbot.fdsa.www.test.evilcorp.com"],
        config={
            "dns": {"minimal": False, "disable": False, "search_distance": 5, "wildcard_ignore": []},
            "speculate": True,
        },
    )
    await scan._prep()
    await scan.helpers.dns._mock_dns(txt_mock_data)

    events = [e async for e in scan.async_start()]

    assert len(events) == 12
    assert len([e for e in events if e.type == "DNS_NAME"]) == 5
    assert len([e for e in events if e.type == "RAW_DNS_RECORD"]) == 4
    assert sorted([e.data for e in events if e.type == "DNS_NAME"]) == [
        "_wildcard.test.evilcorp.com",
        "bbot.fdsa.www.test.evilcorp.com",
        "evilcorp.com",
        "test.evilcorp.com",
        "www.test.evilcorp.com",
    ]

    dns_names_by_host = {e.host: e for e in events if e.type == "DNS_NAME"}
    assert dns_names_by_host["evilcorp.com"].tags == {
        "domain",
        "private-ip",
        "in-scope",
        "a-record",
    }
    assert dns_names_by_host["evilcorp.com"].resolved_hosts == {"127.0.0.1"}
    assert dns_names_by_host["test.evilcorp.com"].tags == {
        "subdomain",
        "private-ip",
        "in-scope",
        "a-record",
        "txt-record",
    }
    assert dns_names_by_host["test.evilcorp.com"].resolved_hosts == {"127.0.0.2"}
    assert dns_names_by_host["_wildcard.test.evilcorp.com"].tags == {
        "subdomain",
        "in-scope",
        "txt-record",
        "txt-wildcard",
        "wildcard",
    }
    assert dns_names_by_host["_wildcard.test.evilcorp.com"].resolved_hosts == set()
    assert dns_names_by_host["www.test.evilcorp.com"].tags == {
        "subdomain",
        "in-scope",
        "aaaa-record",
        "txt-record",
        "txt-wildcard",
        "wildcard",
    }
    assert dns_names_by_host["www.test.evilcorp.com"].resolved_hosts == {"dead::beef"}
    assert dns_names_by_host["bbot.fdsa.www.test.evilcorp.com"].tags == {
        "target",
        "subdomain",
        "in-scope",
        "txt-record",
        "txt-wildcard",
        "wildcard",
        "seed",
    }
    assert dns_names_by_host["bbot.fdsa.www.test.evilcorp.com"].resolved_hosts == set()

    raw_records_by_host = {e.host: e for e in events if e.type == "RAW_DNS_RECORD"}
    assert raw_records_by_host["test.evilcorp.com"].tags == {"subdomain", "in-scope", "txt-record"}
    assert raw_records_by_host["test.evilcorp.com"].resolved_hosts == {"127.0.0.2"}
    assert raw_records_by_host["www.test.evilcorp.com"].tags == {"subdomain", "in-scope", "txt-record", "txt-wildcard"}
    assert raw_records_by_host["www.test.evilcorp.com"].resolved_hosts == {"dead::beef"}
    assert raw_records_by_host["_wildcard.test.evilcorp.com"].tags == {
        "subdomain",
        "in-scope",
        "txt-record",
        "txt-wildcard",
    }
    assert raw_records_by_host["_wildcard.test.evilcorp.com"].resolved_hosts == set()
    assert raw_records_by_host["bbot.fdsa.www.test.evilcorp.com"].tags == {
        "subdomain",
        "in-scope",
        "txt-record",
        "txt-wildcard",
    }
    assert raw_records_by_host["bbot.fdsa.www.test.evilcorp.com"].resolved_hosts == set()

    ### runaway SRV wildcard ###

    # mock a chain of SRV records that recursively point to a deeper subdomain
    # (replacing the original test's dynamic ``custom_lookup_fn``).
    # The regex catch-all is what makes wildcard detection see *.evilcorp.com as a
    # SRV wildcard zone -- without it, random probes during wildcard detection
    # would return no SRV records and the *-wildcard-possible tags would never fire.
    runaway_mock = {
        "evilcorp.com": {"A": ["127.0.0.1"], "SRV": ["0 100 389 test.evilcorp.com."]},
        "test.evilcorp.com": {"AAAA": ["dead::beef"], "SRV": ["0 100 389 test.test.evilcorp.com."]},
        "test.test.evilcorp.com": {"SRV": ["0 100 389 test.test.test.evilcorp.com."]},
        "test.test.test.evilcorp.com": {"SRV": ["0 100 389 test.test.test.test.evilcorp.com."]},
        "test.test.test.test.evilcorp.com": {"SRV": ["0 100 389 test.test.test.test.test.evilcorp.com."]},
        r"regex:^.+\.evilcorp\.com$": {"SRV": ["0 100 389 test.evilcorp.com."]},
    }
    scan = bbot_scanner(
        "evilcorp.com",
        config={
            "dns": {
                "minimal": False,
                "disable": False,
                "search_distance": 5,
                "wildcard_ignore": [],
                "runaway_limit": 3,
            },
        },
    )
    await scan._prep()
    await scan.helpers.dns._mock_dns(runaway_mock)

    events = [e async for e in scan.async_start()]

    assert len(events) == 11
    assert len([e for e in events if e.type == "DNS_NAME"]) == 5
    assert len([e for e in events if e.type == "RAW_DNS_RECORD"]) == 4
    assert sorted([e.data for e in events if e.type == "DNS_NAME"]) == [
        "evilcorp.com",
        "test.evilcorp.com",
        "test.test.evilcorp.com",
        "test.test.test.evilcorp.com",
        "test.test.test.test.evilcorp.com",
    ]

    dns_names_by_host = {e.host: e for e in events if e.type == "DNS_NAME"}
    assert dns_names_by_host["evilcorp.com"].tags == {
        "target",
        "a-record",
        "in-scope",
        "domain",
        "srv-record",
        "private-ip",
        "seed",
    }
    assert dns_names_by_host["test.evilcorp.com"].tags == {
        "in-scope",
        "srv-record",
        "aaaa-record",
        "srv-wildcard-possible",
        "wildcard-possible",
        "subdomain",
    }
    assert dns_names_by_host["test.test.evilcorp.com"].tags == {
        "in-scope",
        "srv-record",
        "srv-wildcard-possible",
        "wildcard-possible",
        "subdomain",
    }
    assert dns_names_by_host["test.test.test.evilcorp.com"].tags == {
        "in-scope",
        "srv-record",
        "srv-wildcard-possible",
        "wildcard-possible",
        "subdomain",
    }
    assert dns_names_by_host["test.test.test.test.evilcorp.com"].tags == {
        "in-scope",
        "srv-record",
        "srv-wildcard-possible",
        "wildcard-possible",
        "subdomain",
        "runaway-dns-3",
    }

    raw_records_by_host = {e.host: e for e in events if e.type == "RAW_DNS_RECORD"}
    assert raw_records_by_host["evilcorp.com"].tags == {"in-scope", "srv-record", "domain"}
    assert raw_records_by_host["test.evilcorp.com"].tags == {
        "in-scope",
        "srv-record",
        "srv-wildcard-possible",
        "subdomain",
    }
    assert raw_records_by_host["test.test.evilcorp.com"].tags == {
        "in-scope",
        "srv-record",
        "srv-wildcard-possible",
        "subdomain",
    }
    assert raw_records_by_host["test.test.test.evilcorp.com"].tags == {
        "in-scope",
        "srv-record",
        "srv-wildcard-possible",
        "subdomain",
    }

    await scan._cleanup()

    ### event resolution + dns_resolve_distance (live github.io wildcard) ###

    scan = bbot_scanner("1.1.1.1")
    await scan._prep()

    # event resolution -- github.io is a stable GitHub Pages wildcard zone
    wildcard_event1 = scan.make_event("wat.asdf.fdsa.github.io", "DNS_NAME", parent=scan.root_event)
    wildcard_event1.scope_distance = 0
    wildcard_event2 = scan.make_event("wats.asd.fdsa.github.io", "DNS_NAME", parent=scan.root_event)
    wildcard_event2.scope_distance = 0
    wildcard_event3 = scan.make_event("github.io", "DNS_NAME", parent=scan.root_event)
    wildcard_event3.scope_distance = 0

    dnsresolve = scan.modules["dnsresolve"]
    await dnsresolve.handle_event(wildcard_event1)
    await dnsresolve.handle_event(wildcard_event2)
    await dnsresolve.handle_event(wildcard_event3)
    assert "wildcard" in wildcard_event1.tags
    assert "a-wildcard" in wildcard_event1.tags
    assert "srv-wildcard" not in wildcard_event1.tags
    assert "wildcard" in wildcard_event2.tags
    assert "a-wildcard" in wildcard_event2.tags
    assert "srv-wildcard" not in wildcard_event2.tags
    assert wildcard_event1.data == "_wildcard.github.io"
    assert wildcard_event2.data == "_wildcard.github.io"
    assert wildcard_event3.data == "github.io"

    # dns resolve distance
    event_distance_0 = scan.make_event("8.8.8.8", module=dnsresolve._make_dummy_module("PTR"), parent=scan.root_event)
    assert event_distance_0.dns_resolve_distance == 0
    event_distance_1 = scan.make_event(
        "evilcorp.com", module=dnsresolve._make_dummy_module("A"), parent=event_distance_0
    )
    assert event_distance_1.dns_resolve_distance == 1
    event_distance_2 = scan.make_event("1.2.3.4", module=dnsresolve._make_dummy_module("PTR"), parent=event_distance_1)
    assert event_distance_2.dns_resolve_distance == 1
    event_distance_3 = scan.make_event(
        "evilcorp.org", module=dnsresolve._make_dummy_module("A"), parent=event_distance_2
    )
    assert event_distance_3.dns_resolve_distance == 2

    await scan._cleanup()

    ### full Scanner test against live github.io ###

    from bbot.scanner import Scanner

    scan2 = Scanner(
        "github.io",
        seeds=["asdfl.gashdgkjsadgsdf.github.io"],
        config={"dns": {"minimal": False}},
    )
    await scan2._prep()
    other_event = scan2.make_event(
        "lkjg.sdfgsg.jgkhajshdsadf.github.io", module=scan2.modules["dnsresolve"], parent=scan2.root_event
    )
    await scan2.ingress_module.queue_event(other_event, {})
    events = [e async for e in scan2.async_start()]

    assert len(events) == 4
    assert 2 == len([e for e in events if e.type == "SCAN"])
    unmodified_wildcard_events = [
        e for e in events if e.type == "DNS_NAME" and e.data == "asdfl.gashdgkjsadgsdf.github.io"
    ]
    assert len(unmodified_wildcard_events) == 1
    assert unmodified_wildcard_events[0].tags.issuperset(
        {
            "a-record",
            "target",
            "aaaa-wildcard",
            "in-scope",
            "subdomain",
            "aaaa-record",
            "wildcard",
            "a-wildcard",
        }
    )
    modified_wildcard_events = [e for e in events if e.type == "DNS_NAME" and e.data == "_wildcard.github.io"]
    assert len(modified_wildcard_events) == 1
    assert modified_wildcard_events[0].tags.issuperset(
        {
            "a-record",
            "aaaa-wildcard",
            "in-scope",
            "subdomain",
            "aaaa-record",
            "wildcard",
            "a-wildcard",
        }
    )
    assert modified_wildcard_events[0].host_original == "lkjg.sdfgsg.jgkhajshdsadf.github.io"

    # full scan with wildcard detection disabled for github.io
    scan2 = Scanner(
        "github.io",
        seeds=["asdfl.gashdgkjsadgsdf.github.io"],
        config={"dns": {"wildcard_ignore": ["github.io"]}},
        exclude_modules=["cloudcheck"],
    )
    await scan2._prep()
    other_event = scan2.make_event(
        "lkjg.sdfgsg.jgkhajshdsadf.github.io", module=scan2.modules["dnsresolve"], parent=scan2.root_event
    )
    await scan2.ingress_module.queue_event(other_event, {})
    events = [e async for e in scan2.async_start()]
    assert len(events) == 4
    assert 2 == len([e for e in events if e.type == "SCAN"])
    unmodified_wildcard_events = [e for e in events if e.type == "DNS_NAME" and "_wildcard" not in e.data]
    assert len(unmodified_wildcard_events) == 2
    assert 1 == len(
        [
            e
            for e in unmodified_wildcard_events
            if e.data == "asdfl.gashdgkjsadgsdf.github.io"
            and e.tags.issuperset(
                {
                    "target",
                    "a-record",
                    "in-scope",
                    "subdomain",
                    "aaaa-record",
                }
            )
        ]
    )
    assert 1 == len(
        [
            e
            for e in unmodified_wildcard_events
            if e.data == "lkjg.sdfgsg.jgkhajshdsadf.github.io"
            and e.tags.issuperset(
                {
                    "a-record",
                    "in-scope",
                    "subdomain",
                    "aaaa-record",
                }
            )
        ]
    )
    modified_wildcard_events = [e for e in events if e.type == "DNS_NAME" and e.data == "_wildcard.github.io"]
    assert len(modified_wildcard_events) == 0


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


# *.evilcorp.com and *.nested.evilcorp.com are both wildcards, but serve different pools.
# The regexes don't overlap: wildcard probes are 10 random lowercase letters.
NESTED_WILDCARD_DNS = {
    "evilcorp.com": {"A": ["127.0.0.1"]},
    r"regex:^[a-z]{10}\.evilcorp\.com$": {"A": ["127.0.0.2"]},
    r"regex:.*\.nested\.evilcorp\.com$": {"A": ["127.0.0.3", "127.0.0.4"]},
    "real.evilcorp.com": {"A": ["127.0.0.5"]},
}


@pytest.mark.asyncio
async def test_nested_wildcards(bbot_scanner):
    """A wildcard nested under a wildcard with a different pool is detected as the nested zone."""
    scan = bbot_scanner("evilcorp.com", config={"dns": {"wildcard_ignore": []}})
    await scan._prep()
    await scan.helpers.dns._mock_dns(NESTED_WILDCARD_DNS)

    # every depth under the nested zone must report the same parent, so the names dedupe
    for query in ("a.nested.evilcorp.com", "a.b.nested.evilcorp.com", "a.b.c.d.e.nested.evilcorp.com"):
        wildcard_rdtypes = await scan.helpers.dns.is_wildcard(query, ["A"])
        assert wildcard_rdtypes.get("A") == (True, "nested.evilcorp.com"), query

    # a name under a wildcard that matches no wildcard pool may be real
    wildcard_rdtypes = await scan.helpers.dns.is_wildcard("real.evilcorp.com", ["A"])
    assert wildcard_rdtypes.get("A") == ("POSSIBLE", "evilcorp.com")

    await scan._cleanup()


@pytest.mark.asyncio
async def test_nested_wildcard_deduplication(bbot_scanner):
    """Names at any depth under a nested wildcard collapse into one _wildcard.* event."""
    from bbot.modules.base import BaseModule

    class DummyModule(BaseModule):
        watched_events = ["DNS_NAME"]
        per_domain_only = True

        async def handle_event(self, event):
            for host in ("a.nested.evilcorp.com", "a.b.nested.evilcorp.com", "a.b.c.d.e.nested.evilcorp.com"):
                await self.emit_event(host, "DNS_NAME", parent=event)

    scan = bbot_scanner(
        "evilcorp.com",
        config={"dns": {"minimal": False, "wildcard_ignore": []}, "omit_event_types": []},
    )
    await scan._prep()
    await scan.helpers.dns._mock_dns(NESTED_WILDCARD_DNS)
    dummy_module = DummyModule(scan)
    scan.modules["dummy_module"] = dummy_module
    events = [e async for e in scan.async_start()]

    dns_names = sorted(e.data for e in events if e.type == "DNS_NAME")
    assert dns_names == ["_wildcard.nested.evilcorp.com", "evilcorp.com"]


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

    # make sure the resolvers used for normal resolution are excluded from brute-forcing
    brute_nameservers = tempwordlist(["1.2.3.4", "8.8.4.4", "4.3.2.1", "8.8.8.8"])
    scan = bbot_scanner(config={"dns": {"brute_nameservers": brute_nameservers}})
    await scan._prep()
    scan.helpers.dns.resolvers = ["8.8.8.8", "8.8.4.4"]
    resolver_file = await scan.helpers.dns.brute.resolver_file()
    resolvers = set(scan.helpers.read_file(resolver_file))
    assert resolvers == {"1.2.3.4", "4.3.2.1"}

    # custom nameservers replace the system ones, and are likewise kept out of
    # the brute-force pool so brute traffic can't rate-limit our own queries
    scan = bbot_scanner(
        config={"dns": {"nameservers": ["8.8.8.8", "8.8.4.4"], "brute_nameservers": brute_nameservers}}
    )
    await scan._prep()
    assert scan.helpers.dns.resolvers == ["8.8.8.8", "8.8.4.4"]
    assert scan.helpers.dns.blastdns.resolvers == ["8.8.8.8:53", "8.8.4.4:53"]
    # resolver_file is what external tools (e.g. nuclei) are pointed at
    assert set(scan.helpers.read_file(scan.helpers.dns.resolver_file)) == {"8.8.8.8", "8.8.4.4"}
    resolver_file = await scan.helpers.dns.brute.resolver_file()
    assert set(scan.helpers.read_file(resolver_file)) == {"1.2.3.4", "4.3.2.1"}

    # with no custom nameservers, the system ones are used
    scan = bbot_scanner()
    await scan._prep()
    assert scan.helpers.dns.resolvers == list(scan.helpers.dns.system_resolvers)


@pytest.mark.asyncio
async def test_dns_brute_client_config(bbot_scanner, monkeypatch):
    """Every dns.brute_* option has to reach the blastdns client.

    blastdns rejects unknown ClientConfig keys, but a value BBOT never passes
    fails silently as a default, which is invisible in scan output.
    """
    from bbot.core.helpers.dns import brute as brute_module

    captured = {}

    class FakeClient:
        def __init__(self, resolvers, config):
            captured["resolvers"] = resolvers
            captured["config"] = config

    monkeypatch.setattr(brute_module, "Client", FakeClient)

    brute_nameservers = tempwordlist(["1.2.3.4", "4.3.2.1"])
    scan = bbot_scanner(
        config={
            "dns": {
                "brute_nameservers": brute_nameservers,
                "brute_threads": 123,
                "brute_inflight_per_resolver": 7,
                "brute_rate_limit": 456,
                "brute_retries": 9,
                "brute_timeout": 0.25,
                "brute_persistent_socket": True,
            }
        }
    )
    await scan._prep()
    await scan.helpers.dns.brute.client()

    config = captured["config"]
    assert config.max_concurrency == 123
    assert config.max_inflight_per_resolver == 7
    assert config.rate_limit == 456
    assert config.max_retries == 9
    assert config.request_timeout_ms == 250
    assert config.persistent_socket is True
    # brute-force names are unique by construction, so a cache is pure overhead
    assert config.cache_capacity == 0

    # a rate limit of 0 means unlimited, which blastdns spells as None
    scan = bbot_scanner(config={"dns": {"brute_nameservers": brute_nameservers, "brute_rate_limit": 0}})
    await scan._prep()
    await scan.helpers.dns.brute.client()
    assert captured["config"].rate_limit is None
    # the shipped default must not silently drift back to a slow tail
    assert captured["config"].request_timeout_ms == 500
    # one socket per resolver keeps NAT state bounded by the resolver count instead
    # of growing with query volume, so it has to stay on by default
    assert captured["config"].persistent_socket is True

    # and it stays overridable, for anywhere the extra sockets are the tighter bound
    scan = bbot_scanner(config={"dns": {"brute_nameservers": brute_nameservers, "brute_persistent_socket": False}})
    await scan._prep()
    await scan.helpers.dns.brute.client()
    assert captured["config"].persistent_socket is False

    # An unusable nameserver fails loudly instead of being silently ignored.
    # Validation is blastdns's, so it happens when the client is built.
    scan = bbot_scanner(config={"dns": {"nameservers": ["not-an-ip"]}})
    with pytest.raises(ValidationError, match="dns.nameservers"):
        _ = scan.helpers.dns.resolvers

    # _prep() builds the client up front, so a bad nameserver aborts the scan there
    # instead of surfacing once per event inside dnsresolve
    scan = bbot_scanner(config={"dns": {"nameservers": ["not-an-ip"]}})
    with pytest.raises(ValidationError, match="dns.nameservers"):
        await scan._prep()

    # a DNS-disabled scan never resolves, so it must not be blocked by that check
    scan = bbot_scanner(config={"dns": {"nameservers": ["not-an-ip"], "disable": True}})
    await scan._prep()


@pytest.mark.asyncio
async def test_dnsresolve_incoming_lanes(bbot_scanner):
    from bbot.core.helpers.async_helpers import LaneQueue

    scan = bbot_scanner("evilcorp.com")
    await scan._prep()
    dnsresolve = scan.modules["dnsresolve"]

    dns_name = scan.make_event("www.evilcorp.com", "DNS_NAME", parent=scan.root_event)
    open_port = scan.make_event("www.evilcorp.com:443", "OPEN_TCP_PORT", parent=dns_name)
    new_host_url = scan.make_event("http://new.evilcorp.com/", "URL_UNVERIFIED", parent=dns_name)
    finished = scan.make_event("FINISHED", "FINISHED", dummy=True)

    # hosts that still need resolving wait; hosts already resolved upstream (and hostless events) don't
    assert dnsresolve.incoming_lane(dns_name) == 1
    assert dnsresolve.incoming_lane(new_host_url) == 1
    assert dnsresolve.incoming_lane(open_port) == 0
    assert dnsresolve.incoming_lane(finished) == 0

    # the queue feeding dnsresolve is divided by those lanes
    queue = dnsresolve.incoming_event_queue
    assert isinstance(queue, LaneQueue)
    for event in (dns_name, new_host_url, open_port):
        queue.put_nowait((event, {}))
    assert [queue.get_nowait()[0] for _ in range(3)] == [open_port, dns_name, new_host_url]


# a host and a child on that host, emitted together by one module (as urlscan and asset_inventory do)
parent_child_mock_data = {
    "evilcorp.com": {"A": ["127.0.0.1"]},
    "ok.evilcorp.com": {"A": ["127.0.0.3"]},
    # resolves to a blacklisted IP
    "bad.evilcorp.com": {"A": ["127.0.0.99"]},
    # in scope only because it resolves to a target IP
    "viaip.othercorp.net": {"A": ["127.0.1.5"]},
    # doesn't resolve
    "dead.evilcorp.com": {},
    # inside a wildcard zone
    r"regex:.*\.wild\.evilcorp\.com$": {"A": ["127.0.0.4"]},
}
parent_child_hosts = (
    "ok.evilcorp.com",
    "bad.evilcorp.com",
    "viaip.othercorp.net",
    "dead.evilcorp.com",
    "foo.wild.evilcorp.com",
)


async def run_parent_child_scan(bbot_scanner, order):
    """
    Scan where a module emits each host in `parent_child_hosts` as a DNS_NAME plus an OPEN_TCP_PORT child of it.

    `order` controls the order dnsresolve handles them in:
    - "parent_first" / "child_first": one dnsresolve worker, FIFO queues, the given event emitted first
    - "lanes": one dnsresolve worker with its real lanes, held until every host and child is queued
    """
    import asyncio
    from bbot.modules.base import BaseModule

    class DummyModule(BaseModule):
        watched_events = ["DNS_NAME"]
        target_only = True

        async def handle_event(self, event):
            for host in parent_child_hosts:
                host_event = self.make_event(host, "DNS_NAME", parent=event)
                port_event = self.make_event(f"{host}:443", "OPEN_TCP_PORT", parent=host_event)
                pair = (port_event, host_event) if order == "child_first" else (host_event, port_event)
                for e in pair:
                    await self.emit_event(e)

    scan = bbot_scanner(
        "evilcorp.com",
        "127.0.1.0/24",
        blacklist=["127.0.0.99"],
        config={"dns": {"threads": 1, "wildcard_ignore": []}},
    )
    await scan._prep()
    await scan.helpers.dns._mock_dns(parent_child_mock_data)
    dummy_module = DummyModule(scan)
    scan.modules["dummy_module"] = dummy_module
    dnsresolve = scan.modules["dnsresolve"]

    queue_filled = None
    if order == "lanes":
        # hold dnsresolve's only worker on the first of these events until the rest are queued behind it
        handle_event = dnsresolve.handle_event

        async def gated_handle_event(event, **kwargs):
            nonlocal queue_filled
            if queue_filled is None and event.host in parent_child_hosts:
                queue_filled = False
                for _ in range(100):
                    if dnsresolve.incoming_event_queue.qsize() >= 2 * len(parent_child_hosts) - 1:
                        queue_filled = True
                        break
                    await asyncio.sleep(0.05)
            return await handle_event(event, **kwargs)

        dnsresolve.handle_event = gated_handle_event
    else:
        # keep emission order all the way into dnsresolve
        dummy_module._outgoing_event_queue = asyncio.Queue()
        dnsresolve.incoming_lane = lambda event: 0

    events = [e async for e in scan.async_start()]
    if order == "lanes":
        assert queue_filled, "hosts and their children never queued up together"
    return events


@pytest.mark.asyncio
@pytest.mark.parametrize("order", ["parent_first", "child_first", "lanes"])
async def test_dnsresolve_parent_child_order(bbot_scanner, order):
    """A host and its child come out of dnsresolve the same way no matter which is handled first."""
    events = await run_parent_child_scan(bbot_scanner, order)

    def find(event_type, data):
        return [e for e in events if e.type == event_type and e.data == data]

    # the parent is resolved, not demoted to DNS_NAME_UNRESOLVED by its child's pass
    assert [e.type for e in events if e.host == "ok.evilcorp.com" and e.type.startswith("DNS_NAME")] == ["DNS_NAME"]
    # the child gets the parent's IPs and scope
    port = find("OPEN_TCP_PORT", "ok.evilcorp.com:443")
    assert len(port) == 1
    assert port[0].resolved_hosts == {"127.0.0.3"}
    assert port[0].scope_distance == 0

    # nothing on a host that resolves to a blacklisted IP gets into the scan
    assert not [e for e in events if e.host == "bad.evilcorp.com"]

    # a host that's in scope only through its IP brings its child into scope with it
    viaip = find("DNS_NAME", "viaip.othercorp.net")
    assert len(viaip) == 1
    assert viaip[0].scope_distance == 0
    port = find("OPEN_TCP_PORT", "viaip.othercorp.net:443")
    assert len(port) == 1
    assert port[0].scope_distance == 0
    assert port[0].resolved_hosts == {"127.0.1.5"}

    # a host that really doesn't resolve is still DNS_NAME_UNRESOLVED
    assert [e.type for e in events if e.host == "dead.evilcorp.com" and e.type.startswith("DNS_NAME")] == [
        "DNS_NAME_UNRESOLVED"
    ]
    port = find("OPEN_TCP_PORT", "dead.evilcorp.com:443")
    assert len(port) == 1
    assert not port[0].resolved_hosts

    # a wildcard host collapses (once per emitting module), and its child keeps its own host
    wild = [e.data for e in events if e.type.startswith("DNS_NAME") and e.data.endswith(".wild.evilcorp.com")]
    assert wild and set(wild) == {"_wildcard.wild.evilcorp.com"}
    port = find("OPEN_TCP_PORT", "foo.wild.evilcorp.com:443")
    assert len(port) == 1
    assert port[0].resolved_hosts == {"127.0.0.4"}


@pytest.mark.asyncio
@pytest.mark.parametrize("release", ["first_arrived_first", "last_arrived_first", "together"])
async def test_dnsresolve_parent_child_interleaved(bbot_scanner, release):
    """A host's DNS_NAME and its child give the same result when their lookups of that host overlap, in any order."""
    import asyncio
    from bbot.modules.base import BaseModule

    hosts = ("ok.evilcorp.com", "bad.evilcorp.com")

    class DummyModule(BaseModule):
        watched_events = ["DNS_NAME"]
        target_only = True

        async def handle_event(self, event):
            for host in hosts:
                host_event = self.make_event(host, "DNS_NAME", parent=event)
                await self.emit_event(host_event)
                await self.emit_event(f"{host}:443", "OPEN_TCP_PORT", parent=host_event)

    scan = bbot_scanner("evilcorp.com", blacklist=["127.0.0.99"])
    await scan._prep()
    await scan.helpers.dns._mock_dns(parent_child_mock_data)
    scan.modules["dummy_module"] = DummyModule(scan)

    # hold every A lookup of these hosts until both the DNS_NAME's pass and the child's pass are waiting on it
    dns = scan.helpers.dns
    resolve_multi_full = dns.resolve_multi_full
    waiting = {host: [] for host in hosts}
    all_waiting = {host: asyncio.Event() for host in hosts}

    async def held_resolve_multi_full(query, rdtypes):
        if query in waiting and "A" in rdtypes and len(waiting[query]) < 2:
            gate, done = asyncio.Event(), asyncio.Event()
            waiting[query].append((gate, done))
            if len(waiting[query]) == 2:
                all_waiting[query].set()
            await gate.wait()
            try:
                return await resolve_multi_full(query, rdtypes)
            finally:
                # set before returning, so the released pass applies its results before the next one is released
                done.set()
        return await resolve_multi_full(query, rdtypes)

    dns.resolve_multi_full = held_resolve_multi_full

    async def release_lookups(host):
        try:
            await asyncio.wait_for(all_waiting[host].wait(), timeout=10)
        except asyncio.TimeoutError:
            # only one pass looked the host up; let the scan finish so the assertions below report it
            for gate, _ in waiting[host]:
                gate.set()
            return
        lookups = list(waiting[host])
        if release == "last_arrived_first":
            lookups.reverse()
        if release == "together":
            for gate, _ in lookups:
                gate.set()
        else:
            for gate, done in lookups:
                gate.set()
                await done.wait()
                # let the released pass apply its results
                await asyncio.sleep(0.1)

    releasers = [asyncio.create_task(release_lookups(host)) for host in hosts]
    events = [e async for e in scan.async_start()]
    # both passes looked the host up themselves, and their lookups overlapped
    for task in releasers:
        await task
    assert all(len(lookups) == 2 for lookups in waiting.values())

    assert [e.type for e in events if e.host == "ok.evilcorp.com" and e.type.startswith("DNS_NAME")] == ["DNS_NAME"]
    port = [e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "ok.evilcorp.com:443"]
    assert len(port) == 1
    assert port[0].resolved_hosts == {"127.0.0.3"}
    assert not [e for e in events if e.host == "bad.evilcorp.com"]
