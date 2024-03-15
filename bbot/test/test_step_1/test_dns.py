from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_dns(bbot_scanner, bbot_config, mock_dns):
    scan = bbot_scanner("1.1.1.1", config=bbot_config)
    helpers = scan.helpers

    # lowest level functions
    a_responses = await helpers._resolve_hostname("one.one.one.one")
    aaaa_responses = await helpers._resolve_hostname("one.one.one.one", rdtype="AAAA")
    ip_responses = await helpers._resolve_ip("1.1.1.1")
    assert a_responses[0].response.answer[0][0].address in ("1.1.1.1", "1.0.0.1")
    assert aaaa_responses[0].response.answer[0][0].address in ("2606:4700:4700::1111", "2606:4700:4700::1001")
    assert ip_responses[0].response.answer[0][0].target.to_text() in ("one.one.one.one.",)

    # mid level functions
    _responses, errors = await helpers.resolve_raw("one.one.one.one")
    responses = []
    for rdtype, response in _responses:
        for answers in response:
            responses += list(helpers.extract_targets(answers))
    assert ("A", "1.1.1.1") in responses
    _responses, errors = await helpers.resolve_raw("one.one.one.one", rdtype="AAAA")
    responses = []
    for rdtype, response in _responses:
        for answers in response:
            responses += list(helpers.extract_targets(answers))
    assert ("AAAA", "2606:4700:4700::1111") in responses
    _responses, errors = await helpers.resolve_raw("1.1.1.1")
    responses = []
    for rdtype, response in _responses:
        for answers in response:
            responses += list(helpers.extract_targets(answers))
    assert ("PTR", "one.one.one.one") in responses

    # high level functions
    assert "1.1.1.1" in await helpers.resolve("one.one.one.one")
    assert "2606:4700:4700::1111" in await helpers.resolve("one.one.one.one", type="AAAA")
    assert "one.one.one.one" in await helpers.resolve("1.1.1.1")
    for rdtype in ("NS", "SOA", "MX", "TXT"):
        assert len(await helpers.resolve("google.com", type=rdtype)) > 0

    # batch resolution
    batch_results = [r async for r in helpers.resolve_batch(["1.1.1.1", "one.one.one.one"])]
    assert len(batch_results) == 2
    batch_results = dict(batch_results)
    assert any([x in batch_results["one.one.one.one"] for x in ("1.1.1.1", "1.0.0.1")])
    assert "one.one.one.one" in batch_results["1.1.1.1"]

    # "any" type
    resolved = await helpers.resolve("google.com", type="any")
    assert any([helpers.is_subdomain(h) for h in resolved])

    # dns cache
    helpers.dns._dns_cache.clear()
    assert hash(f"1.1.1.1:PTR") not in helpers.dns._dns_cache
    assert hash(f"one.one.one.one:A") not in helpers.dns._dns_cache
    assert hash(f"one.one.one.one:AAAA") not in helpers.dns._dns_cache
    await helpers.resolve("1.1.1.1", use_cache=False)
    await helpers.resolve("one.one.one.one", use_cache=False)
    assert hash(f"1.1.1.1:PTR") not in helpers.dns._dns_cache
    assert hash(f"one.one.one.one:A") not in helpers.dns._dns_cache
    assert hash(f"one.one.one.one:AAAA") not in helpers.dns._dns_cache

    await helpers.resolve("1.1.1.1")
    assert hash(f"1.1.1.1:PTR") in helpers.dns._dns_cache
    await helpers.resolve("one.one.one.one")
    assert hash(f"one.one.one.one:A") in helpers.dns._dns_cache
    assert hash(f"one.one.one.one:AAAA") in helpers.dns._dns_cache

    # Ensure events with hosts have resolved_hosts attribute populated
    resolved_hosts_event1 = scan.make_event("one.one.one.one", "DNS_NAME", dummy=True)
    resolved_hosts_event2 = scan.make_event("http://one.one.one.one/", "URL_UNVERIFIED", dummy=True)
    event_tags1, event_whitelisted1, event_blacklisted1, children1 = await scan.helpers.resolve_event(
        resolved_hosts_event1
    )
    event_tags2, event_whitelisted2, event_blacklisted2, children2 = await scan.helpers.resolve_event(
        resolved_hosts_event2
    )
    assert "1.1.1.1" in [str(x) for x in children1["A"]]
    assert "1.1.1.1" in [str(x) for x in children2["A"]]
    assert set(children1.keys()) == set(children2.keys())

    dns_config = OmegaConf.create({"dns_resolution": True})
    dns_config = OmegaConf.merge(bbot_config, dns_config)
    scan2 = bbot_scanner("evilcorp.com", config=dns_config)
    mock_dns(
        scan2,
        {
            "evilcorp.com": {"TXT": ['"v=spf1 include:cloudprovider.com ~all"']},
            "cloudprovider.com": {"A": ["1.2.3.4"]},
        },
    )
    events = [e async for e in scan2.async_start()]
    assert 1 == len(
        [e for e in events if e.type == "DNS_NAME" and e.data == "cloudprovider.com" and "affiliate" in e.tags]
    )


@pytest.mark.asyncio
async def test_wildcards(bbot_scanner, bbot_config):
    scan = bbot_scanner("1.1.1.1", config=bbot_config)
    helpers = scan.helpers

    # wildcards
    wildcard_domains = await helpers.is_wildcard_domain("asdf.github.io")
    assert hash("github.io") in helpers.dns._wildcard_cache
    assert hash("asdf.github.io") in helpers.dns._wildcard_cache
    assert "github.io" in wildcard_domains
    assert "A" in wildcard_domains["github.io"]
    assert "SRV" not in wildcard_domains["github.io"]
    assert wildcard_domains["github.io"]["A"] and all(helpers.is_ip(r) for r in wildcard_domains["github.io"]["A"])
    helpers.dns._wildcard_cache.clear()

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
    assert not hash("asdf.github.io") in helpers.dns._wildcard_cache
    assert not hash("asdf.asdf.github.io") in helpers.dns._wildcard_cache
    assert not hash("asdf.asdf.asdf.github.io") in helpers.dns._wildcard_cache
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
    assert "wildcard-domain" in wildcard_event3.tags
    assert "a-wildcard-domain" in wildcard_event3.tags
    assert "srv-wildcard-domain" not in wildcard_event3.tags
