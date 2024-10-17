from ..bbot_fixtures import *

from bbot.core.helpers.dns.helpers import extract_targets, service_record, common_srvs


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
async def test_dns_engine(bbot_scanner):
    scan = bbot_scanner()
    await scan.helpers._mock_dns(
        {"one.one.one.one": {"A": ["1.1.1.1"]}, "1.1.1.1.in-addr.arpa": {"PTR": ["one.one.one.one"]}}
    )
    result = await scan.helpers.resolve("one.one.one.one")
    assert "1.1.1.1" in result
    assert not "2606:4700:4700::1111" in result

    results = [_ async for _ in scan.helpers.resolve_batch(("one.one.one.one", "1.1.1.1"))]
    pass_1 = False
    pass_2 = False
    for query, result in results:
        if query == "one.one.one.one" and "1.1.1.1" in result:
            pass_1 = True
        elif query == "1.1.1.1" and "one.one.one.one" in result:
            pass_2 = True
    assert pass_1 and pass_2

    results = [_ async for _ in scan.helpers.resolve_raw_batch((("one.one.one.one", "A"), ("1.1.1.1", "PTR")))]
    pass_1 = False
    pass_2 = False
    for (query, rdtype), (answers, errors) in results:
        results = []
        for answer in answers:
            for t in extract_targets(answer):
                results.append(t[1])
        if query == "one.one.one.one" and "1.1.1.1" in results:
            pass_1 = True
        elif query == "1.1.1.1" and "one.one.one.one" in results:
            pass_2 = True
    assert pass_1 and pass_2

    from bbot.core.helpers.dns.mock import MockResolver

    # ensure dns records are being properly cleaned
    mockresolver = MockResolver({"evilcorp.com": {"MX": ["0 ."]}})
    mx_records = await mockresolver.resolve("evilcorp.com", rdtype="MX")
    results = set()
    for r in mx_records:
        results.update(extract_targets(r))
    assert not results

    await scan._cleanup()


@pytest.mark.asyncio
async def test_dns_resolution(bbot_scanner):
    scan = bbot_scanner("1.1.1.1")

    from bbot.core.helpers.dns.engine import DNSEngine

    dnsengine = DNSEngine(None)
    await dnsengine._mock_dns(mock_records)

    # lowest level functions
    a_responses = await dnsengine._resolve_hostname("one.one.one.one")
    aaaa_responses = await dnsengine._resolve_hostname("one.one.one.one", rdtype="AAAA")
    ip_responses = await dnsengine._resolve_ip("1.1.1.1")
    assert a_responses[0].response.answer[0][0].address in ("1.1.1.1", "1.0.0.1")
    assert aaaa_responses[0].response.answer[0][0].address in ("2606:4700:4700::1111", "2606:4700:4700::1001")
    assert ip_responses[0].response.answer[0][0].target.to_text() in ("one.one.one.one.",)

    # mid level functions
    answers, errors = await dnsengine.resolve_raw("one.one.one.one", type="A")
    responses = []
    for answer in answers:
        responses += list(extract_targets(answer))
    assert ("A", "1.1.1.1") in responses
    assert not ("AAAA", "2606:4700:4700::1111") in responses
    answers, errors = await dnsengine.resolve_raw("one.one.one.one", type="AAAA")
    responses = []
    for answer in answers:
        responses += list(extract_targets(answer))
    assert not ("A", "1.1.1.1") in responses
    assert ("AAAA", "2606:4700:4700::1111") in responses
    answers, errors = await dnsengine.resolve_raw("1.1.1.1")
    responses = []
    for answer in answers:
        responses += list(extract_targets(answer))
    assert ("PTR", "one.one.one.one") in responses

    await dnsengine._shutdown()

    # high level functions
    dnsengine = DNSEngine(None)
    assert "1.1.1.1" in await dnsengine.resolve("one.one.one.one")
    assert "2606:4700:4700::1111" in await dnsengine.resolve("one.one.one.one", type="AAAA")
    assert "one.one.one.one" in await dnsengine.resolve("1.1.1.1")
    for rdtype in ("NS", "SOA", "MX", "TXT"):
        assert len(await dnsengine.resolve("google.com", type=rdtype)) > 0

    # batch resolution
    batch_results = [r async for r in dnsengine.resolve_batch(["1.1.1.1", "one.one.one.one"])]
    assert len(batch_results) == 2
    batch_results = dict(batch_results)
    assert any([x in batch_results["one.one.one.one"] for x in ("1.1.1.1", "1.0.0.1")])
    assert "one.one.one.one" in batch_results["1.1.1.1"]

    # custom batch resolution
    batch_results = [r async for r in dnsengine.resolve_raw_batch([("1.1.1.1", "PTR"), ("one.one.one.one", "A")])]
    batch_results_new = []
    for query, (answers, errors) in batch_results:
        for answer in answers:
            batch_results_new.append((answer.to_text(), answer.rdtype.name))
    assert len(batch_results_new) == 3
    assert any(answer == "1.0.0.1" and rdtype == "A" for answer, rdtype in batch_results_new)
    assert any(answer == "one.one.one.one." and rdtype == "PTR" for answer, rdtype in batch_results_new)

    # dns cache
    dnsengine._dns_cache.clear()
    assert hash(("1.1.1.1", "PTR")) not in dnsengine._dns_cache
    assert hash(("one.one.one.one", "A")) not in dnsengine._dns_cache
    assert hash(("one.one.one.one", "AAAA")) not in dnsengine._dns_cache
    await dnsengine.resolve("1.1.1.1", use_cache=False)
    await dnsengine.resolve("one.one.one.one", use_cache=False)
    assert hash(("1.1.1.1", "PTR")) not in dnsengine._dns_cache
    assert hash(("one.one.one.one", "A")) not in dnsengine._dns_cache
    assert hash(("one.one.one.one", "AAAA")) not in dnsengine._dns_cache

    await dnsengine.resolve("1.1.1.1")
    assert hash(("1.1.1.1", "PTR")) in dnsengine._dns_cache
    await dnsengine.resolve("one.one.one.one", type="A")
    assert hash(("one.one.one.one", "A")) in dnsengine._dns_cache
    assert not hash(("one.one.one.one", "AAAA")) in dnsengine._dns_cache
    dnsengine._dns_cache.clear()
    await dnsengine.resolve("one.one.one.one", type="AAAA")
    assert hash(("one.one.one.one", "AAAA")) in dnsengine._dns_cache
    assert not hash(("one.one.one.one", "A")) in dnsengine._dns_cache

    await dnsengine._shutdown()

    # Ensure events with hosts have resolved_hosts attribute populated
    await scan._prep()
    resolved_hosts_event1 = scan.make_event("one.one.one.one", "DNS_NAME", parent=scan.root_event)
    resolved_hosts_event2 = scan.make_event("http://one.one.one.one/", "URL_UNVERIFIED", parent=scan.root_event)
    dnsresolve = scan.modules["dnsresolve"]
    await dnsresolve.handle_event(resolved_hosts_event1)
    await dnsresolve.handle_event(resolved_hosts_event2)
    assert "1.1.1.1" in resolved_hosts_event2.resolved_hosts
    # URL event should not have dns_children
    assert not resolved_hosts_event2.dns_children
    assert resolved_hosts_event1.resolved_hosts == resolved_hosts_event2.resolved_hosts
    # DNS_NAME event should have dns_children
    assert "1.1.1.1" in resolved_hosts_event1.dns_children["A"]
    assert "A" in resolved_hosts_event1.raw_dns_records
    assert "AAAA" in resolved_hosts_event1.raw_dns_records
    assert "a-record" in resolved_hosts_event1.tags
    assert not "a-record" in resolved_hosts_event2.tags

    scan2 = bbot_scanner("evilcorp.com", config={"dns": {"minimal": False}})
    await scan2.helpers.dns._mock_dns(
        {
            "evilcorp.com": {"TXT": ['"v=spf1 include:cloudprovider.com ~all"']},
            "cloudprovider.com": {"A": ["1.2.3.4"]},
        },
    )
    events = [e async for e in scan2.async_start()]
    assert 1 == len(
        [e for e in events if e.type == "DNS_NAME" and e.data == "cloudprovider.com" and "affiliate" in e.tags]
    )

    await scan._cleanup()
    await scan2._cleanup()


@pytest.mark.asyncio
async def test_wildcards(bbot_scanner):

    scan = bbot_scanner("1.1.1.1")
    helpers = scan.helpers

    from bbot.core.helpers.dns.engine import DNSEngine, all_rdtypes

    dnsengine = DNSEngine(None, debug=True)

    # is_wildcard_domain
    wildcard_domains = await dnsengine.is_wildcard_domain("asdf.github.io", all_rdtypes)
    assert len(dnsengine._wildcard_cache) == len(all_rdtypes) + (len(all_rdtypes) - 2)
    for rdtype in all_rdtypes:
        assert hash(("github.io", rdtype)) in dnsengine._wildcard_cache
        if not rdtype in ("A", "AAAA"):
            assert hash(("asdf.github.io", rdtype)) in dnsengine._wildcard_cache
    assert "github.io" in wildcard_domains
    assert "A" in wildcard_domains["github.io"]
    assert "SRV" not in wildcard_domains["github.io"]
    assert wildcard_domains["github.io"]["A"] and all(helpers.is_ip(r) for r in wildcard_domains["github.io"]["A"][0])
    dnsengine._wildcard_cache.clear()

    # is_wildcard
    for test_domain in ("blacklanternsecurity.github.io", "asdf.asdf.asdf.github.io"):
        wildcard_rdtypes = await dnsengine.is_wildcard(test_domain, all_rdtypes)
        assert "A" in wildcard_rdtypes
        assert "SRV" not in wildcard_rdtypes
        assert wildcard_rdtypes["A"] == (True, "github.io")
        assert wildcard_rdtypes["AAAA"] == (True, "github.io")
        assert len(dnsengine._wildcard_cache) == 2
        for rdtype in ("A", "AAAA"):
            assert hash(("github.io", rdtype)) in dnsengine._wildcard_cache
            assert len(dnsengine._wildcard_cache[hash(("github.io", rdtype))]) == 2
            assert len(dnsengine._wildcard_cache[hash(("github.io", rdtype))][0]) > 0
            assert len(dnsengine._wildcard_cache[hash(("github.io", rdtype))][1]) > 0
        dnsengine._wildcard_cache.clear()

    ### wildcard TXT record ###

    custom_lookup = """
def custom_lookup(query, rdtype):
    if rdtype == "TXT" and query.strip(".").endswith("test.evilcorp.com"):
        return {""}
"""

    mock_data = {
        "evilcorp.com": {"A": ["127.0.0.1"]},
        "test.evilcorp.com": {"A": ["127.0.0.2"]},
        "www.test.evilcorp.com": {"AAAA": ["dead::beef"]},
    }

    # basic sanity checks

    await dnsengine._mock_dns(mock_data, custom_lookup_fn=custom_lookup)

    a_result = await dnsengine.resolve("evilcorp.com")
    assert a_result == {"127.0.0.1"}
    aaaa_result = await dnsengine.resolve("www.test.evilcorp.com", type="AAAA")
    assert aaaa_result == {"dead::beef"}
    txt_result = await dnsengine.resolve("asdf.www.test.evilcorp.com", type="TXT")
    assert txt_result == set()
    txt_result_raw, errors = await dnsengine.resolve_raw("asdf.www.test.evilcorp.com", type="TXT")
    txt_result_raw = list(txt_result_raw)
    assert txt_result_raw

    await dnsengine._shutdown()

    # first, we check with wildcard detection disabled

    scan = bbot_scanner(
        "bbot.fdsa.www.test.evilcorp.com",
        whitelist=["evilcorp.com"],
        config={
            "dns": {"minimal": False, "disable": False, "search_distance": 5, "wildcard_ignore": ["evilcorp.com"]},
            "speculate": True,
        },
    )
    await scan.helpers.dns._mock_dns(mock_data, custom_lookup_fn=custom_lookup)

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
    assert dns_names_by_host["evilcorp.com"].tags == {"domain", "private-ip", "in-scope", "a-record"}
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
        "bbot.fdsa.www.test.evilcorp.com",
        whitelist=["evilcorp.com"],
        config={
            "dns": {"minimal": False, "disable": False, "search_distance": 5, "wildcard_ignore": []},
            "speculate": True,
        },
    )
    await scan.helpers.dns._mock_dns(mock_data, custom_lookup_fn=custom_lookup)

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
    assert dns_names_by_host["evilcorp.com"].tags == {"domain", "private-ip", "in-scope", "a-record"}
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

    custom_lookup = """
def custom_lookup(query, rdtype):
    if rdtype == "SRV" and query.strip(".").endswith("evilcorp.com"):
        return {f"0 100 389 test.{query}"}
"""

    mock_data = {
        "evilcorp.com": {"A": ["127.0.0.1"]},
        "test.evilcorp.com": {"AAAA": ["dead::beef"]},
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
    await scan.helpers.dns._mock_dns(mock_data, custom_lookup_fn=custom_lookup)

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

    scan = bbot_scanner("1.1.1.1")
    helpers = scan.helpers

    # event resolution
    wildcard_event1 = scan.make_event("wat.asdf.fdsa.github.io", "DNS_NAME", parent=scan.root_event)
    wildcard_event1.scope_distance = 0
    wildcard_event2 = scan.make_event("wats.asd.fdsa.github.io", "DNS_NAME", parent=scan.root_event)
    wildcard_event2.scope_distance = 0
    wildcard_event3 = scan.make_event("github.io", "DNS_NAME", parent=scan.root_event)
    wildcard_event3.scope_distance = 0

    await scan._prep()
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
    event_distance_0 = scan.make_event(
        "8.8.8.8", module=scan.modules["dnsresolve"]._make_dummy_module("PTR"), parent=scan.root_event
    )
    assert event_distance_0.dns_resolve_distance == 0
    event_distance_1 = scan.make_event(
        "evilcorp.com", module=scan.modules["dnsresolve"]._make_dummy_module("A"), parent=event_distance_0
    )
    assert event_distance_1.dns_resolve_distance == 1
    event_distance_2 = scan.make_event(
        "1.2.3.4", module=scan.modules["dnsresolve"]._make_dummy_module("PTR"), parent=event_distance_1
    )
    assert event_distance_2.dns_resolve_distance == 1
    event_distance_3 = scan.make_event(
        "evilcorp.org", module=scan.modules["dnsresolve"]._make_dummy_module("A"), parent=event_distance_2
    )
    assert event_distance_3.dns_resolve_distance == 2

    await scan._cleanup()

    from bbot.scanner import Scanner

    # test with full scan
    scan2 = Scanner("asdfl.gashdgkjsadgsdf.github.io", whitelist=["github.io"], config={"dns": {"minimal": False}})
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

    # test with full scan (wildcard detection disabled for domain)
    scan2 = Scanner(
        "asdfl.gashdgkjsadgsdf.github.io",
        whitelist=["github.io"],
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
async def test_dns_raw_records(bbot_scanner):

    from bbot.modules.base import BaseModule

    class DummyModule(BaseModule):
        watched_events = ["*"]

        async def setup(self):
            self.events = []
            return True

        async def handle_event(self, event):
            self.events.append(event)

    # scan without omitted event type
    scan = bbot_scanner("one.one.one.one", "1.1.1.1", config={"dns": {"minimal": False}, "omit_event_types": []})
    await scan.helpers.dns._mock_dns(mock_records)
    dummy_module = DummyModule(scan)
    scan.modules["dummy_module"] = dummy_module
    events = [e async for e in scan.async_start()]
    assert 1 == len([e for e in events if e.type == "RAW_DNS_RECORD"])
    assert 1 == len(
        [
            e
            for e in events
            if e.type == "RAW_DNS_RECORD"
            and e.host == "one.one.one.one"
            and e.data["host"] == "one.one.one.one"
            and e.data["type"] == "TXT"
            and e.data["answer"]
            == '"v=spf1 ip4:103.151.192.0/23 ip4:185.12.80.0/22 ip4:188.172.128.0/20 ip4:192.161.144.0/20 ip4:216.198.0.0/18 ~all"'
            and e.discovery_context == "TXT lookup on one.one.one.one produced RAW_DNS_RECORD"
        ]
    )
    assert 1 == len(
        [
            e
            for e in dummy_module.events
            if e.type == "RAW_DNS_RECORD"
            and e.host == "one.one.one.one"
            and e.data["host"] == "one.one.one.one"
            and e.data["type"] == "TXT"
            and e.data["answer"]
            == '"v=spf1 ip4:103.151.192.0/23 ip4:185.12.80.0/22 ip4:188.172.128.0/20 ip4:192.161.144.0/20 ip4:216.198.0.0/18 ~all"'
            and e.discovery_context == "TXT lookup on one.one.one.one produced RAW_DNS_RECORD"
        ]
    )
    # scan with omitted event type
    scan = bbot_scanner("one.one.one.one", config={"dns": {"minimal": False}, "omit_event_types": ["RAW_DNS_RECORD"]})
    await scan.helpers.dns._mock_dns(mock_records)
    dummy_module = DummyModule(scan)
    scan.modules["dummy_module"] = dummy_module
    events = [e async for e in scan.async_start()]
    # no raw records should be emitted
    assert 0 == len([e for e in events if e.type == "RAW_DNS_RECORD"])
    assert 0 == len([e for e in dummy_module.events if e.type == "RAW_DNS_RECORD"])

    # scan with watching module
    DummyModule.watched_events = ["RAW_DNS_RECORD"]
    scan = bbot_scanner("one.one.one.one", config={"dns": {"minimal": False}, "omit_event_types": ["RAW_DNS_RECORD"]})
    await scan.helpers.dns._mock_dns(mock_records)
    dummy_module = DummyModule(scan)
    scan.modules["dummy_module"] = dummy_module
    events = [e async for e in scan.async_start()]
    # no raw records should be ouptut
    assert 0 == len([e for e in events if e.type == "RAW_DNS_RECORD"])
    # but they should still make it to the module
    assert 1 == len(
        [
            e
            for e in dummy_module.events
            if e.type == "RAW_DNS_RECORD"
            and e.host == "one.one.one.one"
            and e.data["host"] == "one.one.one.one"
            and e.data["type"] == "TXT"
            and e.data["answer"]
            == '"v=spf1 ip4:103.151.192.0/23 ip4:185.12.80.0/22 ip4:188.172.128.0/20 ip4:192.161.144.0/20 ip4:216.198.0.0/18 ~all"'
            and e.discovery_context == "TXT lookup on one.one.one.one produced RAW_DNS_RECORD"
        ]
    )


@pytest.mark.asyncio
async def test_dns_graph_structure(bbot_scanner):
    scan = bbot_scanner("https://evilcorp.com", config={"dns": {"search_distance": 1, "minimal": False}})
    await scan.helpers.dns._mock_dns(
        {
            "evilcorp.com": {
                "CNAME": [
                    "www.evilcorp.com",
                ]
            },
            "www.evilcorp.com": {"CNAME": ["test.evilcorp.com"]},
            "test.evilcorp.com": {"A": ["127.0.0.1"]},
        }
    )
    events = [e async for e in scan.async_start()]
    assert len(events) == 6
    non_scan_events = [e for e in events if e.type != "SCAN"]
    assert sorted([e.type for e in non_scan_events]) == ["DNS_NAME", "DNS_NAME", "DNS_NAME", "URL_UNVERIFIED"]
    events_by_data = {e.data: e for e in non_scan_events}
    assert set(events_by_data) == {"https://evilcorp.com/", "evilcorp.com", "www.evilcorp.com", "test.evilcorp.com"}
    assert events_by_data["test.evilcorp.com"].parent.data == "www.evilcorp.com"
    assert str(events_by_data["test.evilcorp.com"].module) == "CNAME"
    assert events_by_data["www.evilcorp.com"].parent.data == "evilcorp.com"
    assert str(events_by_data["www.evilcorp.com"].module) == "CNAME"
    assert events_by_data["evilcorp.com"].parent.data == "https://evilcorp.com/"
    assert str(events_by_data["evilcorp.com"].module) == "host"


@pytest.mark.asyncio
async def test_dns_helpers(bbot_scanner):
    assert service_record("") == False
    assert service_record("localhost") == False
    assert service_record("www.example.com") == False
    assert service_record("www.example.com", "SRV") == True
    assert service_record("_custom._service.example.com", "SRV") == True
    assert service_record("_custom._service.example.com", "A") == False
    # top 100 most common SRV records
    for srv_record in common_srvs[:100]:
        hostname = f"{srv_record}.example.com"
        assert service_record(hostname) == True

    # make sure system nameservers are excluded from use by DNS brute force
    brute_nameservers = tempwordlist(["1.2.3.4", "8.8.4.4", "4.3.2.1", "8.8.8.8"])
    scan = bbot_scanner(config={"dns": {"brute_nameservers": brute_nameservers}})
    scan.helpers.dns.system_resolvers = ["8.8.8.8", "8.8.4.4"]
    resolver_file = await scan.helpers.dns.brute.resolver_file()
    resolvers = set(scan.helpers.read_file(resolver_file))
    assert resolvers == {"1.2.3.4", "4.3.2.1"}
