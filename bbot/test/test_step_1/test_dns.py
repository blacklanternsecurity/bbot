from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_dns(bbot_scanner, bbot_config):
    scan = bbot_scanner("8.8.8.8")
    helpers = scan.helpers

    # lowest level functions
    a_responses = await helpers._resolve_hostname("dns.google")
    aaaa_responses = await helpers._resolve_hostname("dns.google", rdtype="AAAA")
    ip_responses = await helpers._resolve_ip("8.8.8.8")
    assert a_responses[0].response.answer[0][0].address in ("8.8.8.8", "8.8.4.4")
    assert aaaa_responses[0].response.answer[0][0].address in ("2001:4860:4860::8888", "2001:4860:4860::8844")
    assert ip_responses[0].response.answer[0][0].target.to_text() in ("dns.google.",)

    # mid level functions
    _responses, errors = await helpers.resolve_raw("dns.google")
    responses = []
    for rdtype, response in _responses:
        for answers in response:
            responses += list(helpers.extract_targets(answers))
    assert ("A", "8.8.8.8") in responses
    _responses, errors = await helpers.resolve_raw("dns.google", rdtype="AAAA")
    responses = []
    for rdtype, response in _responses:
        for answers in response:
            responses += list(helpers.extract_targets(answers))
    assert ("AAAA", "2001:4860:4860::8888") in responses
    _responses, errors = await helpers.resolve_raw("8.8.8.8")
    responses = []
    for rdtype, response in _responses:
        for answers in response:
            responses += list(helpers.extract_targets(answers))
    assert ("PTR", "dns.google") in responses

    # high level functions
    assert "8.8.8.8" in await helpers.resolve("dns.google")
    assert "2001:4860:4860::8888" in await helpers.resolve("dns.google", type="AAAA")
    assert "dns.google" in await helpers.resolve("8.8.8.8")
    for rdtype in ("NS", "SOA", "MX", "TXT"):
        assert len(await helpers.resolve("google.com", type=rdtype)) > 0

    # batch resolution
    batch_results = [r async for r in helpers.resolve_batch(["8.8.8.8", "dns.google"])]
    assert len(batch_results) == 2
    batch_results = dict(batch_results)
    assert any([x in batch_results["dns.google"] for x in ("8.8.8.8", "8.8.4.4")])
    assert "dns.google" in batch_results["8.8.8.8"]

    # "any" type
    resolved = await helpers.resolve("google.com", type="any")
    assert any([helpers.is_subdomain(h) for h in resolved])

    # dns cache
    assert hash(f"8.8.8.8:PTR") not in helpers.dns._dns_cache
    assert hash(f"dns.google:A") not in helpers.dns._dns_cache
    assert hash(f"dns.google:AAAA") not in helpers.dns._dns_cache
    await helpers.resolve("8.8.8.8", cache_result=True)
    assert hash(f"8.8.8.8:PTR") in helpers.dns._dns_cache
    await helpers.resolve("dns.google", cache_result=True)
    assert hash(f"dns.google:A") in helpers.dns._dns_cache
    assert hash(f"dns.google:AAAA") in helpers.dns._dns_cache

    # wildcards
    wildcard_domains = await helpers.is_wildcard_domain("asdf.github.io")
    assert "github.io" in wildcard_domains
    assert "A" in wildcard_domains["github.io"]
    assert "SRV" not in wildcard_domains["github.io"]
    assert wildcard_domains["github.io"]["A"] and all(helpers.is_ip(r) for r in wildcard_domains["github.io"]["A"])

    wildcard_rdtypes = await helpers.is_wildcard("blacklanternsecurity.github.io")
    assert "A" in wildcard_rdtypes
    assert "SRV" not in wildcard_rdtypes
    assert wildcard_rdtypes["A"] == (True, "github.io")
    assert hash("github.io") in helpers.dns._wildcard_cache
    assert len(helpers.dns._wildcard_cache[hash("github.io")]) > 0
    helpers.dns._wildcard_cache.clear()

    wildcard_rdtypes = await helpers.is_wildcard("asdf.asdf.asdf.github.io")
    assert "A" in wildcard_rdtypes
    assert "SRV" not in wildcard_rdtypes
    assert wildcard_rdtypes["A"] == (True, "github.io")
    assert hash("github.io") in helpers.dns._wildcard_cache
    assert len(helpers.dns._wildcard_cache[hash("github.io")]) > 0
    wildcard_event1 = scan.make_event("wat.asdf.fdsa.github.io", "DNS_NAME", dummy=True)
    wildcard_event2 = scan.make_event("wats.asd.fdsa.github.io", "DNS_NAME", dummy=True)
    wildcard_event3 = scan.make_event("github.io", "DNS_NAME", dummy=True)

    # event resolution
    event_tags1, event_whitelisted1, event_blacklisted1, children1 = await scan.helpers.resolve_event(wildcard_event1)
    event_tags2, event_whitelisted2, event_blacklisted2, children2 = await scan.helpers.resolve_event(wildcard_event2)
    event_tags3, event_whitelisted3, event_blacklisted3, children3 = await scan.helpers.resolve_event(wildcard_event3)
    await helpers.handle_wildcard_event(wildcard_event1, children1)
    await helpers.handle_wildcard_event(wildcard_event2, children2)
    await helpers.handle_wildcard_event(wildcard_event3, children3)
    assert "wildcard" in wildcard_event1.tags
    assert "a-wildcard" in wildcard_event1.tags
    assert "srv-wildcard" not in wildcard_event1.tags
    assert "wildcard" in wildcard_event2.tags
    assert "a-wildcard" in wildcard_event2.tags
    assert "srv-wildcard" not in wildcard_event2.tags
    assert wildcard_event1.data == "_wildcard.github.io"
    assert wildcard_event2.data == "_wildcard.github.io"
    assert wildcard_event1.tags == wildcard_event2.tags
    assert "wildcard-domain" in wildcard_event3.tags
    assert "a-wildcard-domain" in wildcard_event3.tags
    assert "srv-wildcard-domain" not in wildcard_event3.tags

    # Ensure events with hosts have resolved_hosts attribute populated
    resolved_hosts_event1 = scan.make_event("dns.google", "DNS_NAME", dummy=True)
    resolved_hosts_event2 = scan.make_event("http://dns.google/", "URL_UNVERIFIED", dummy=True)
    event_tags1, event_whitelisted1, event_blacklisted1, children1 = await scan.helpers.resolve_event(
        resolved_hosts_event1
    )
    event_tags2, event_whitelisted2, event_blacklisted2, children2 = await scan.helpers.resolve_event(
        resolved_hosts_event2
    )
    assert "8.8.8.8" in [str(x) for x in children1["A"]]
    assert "8.8.8.8" in [str(x) for x in children2["A"]]
    assert set(children1.keys()) == set(children2.keys())
