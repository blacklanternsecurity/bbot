import json
import random
import ipaddress

from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_events(events, scan, helpers, bbot_config):
    assert events.ipv4.type == "IP_ADDRESS"
    assert events.ipv6.type == "IP_ADDRESS"
    assert events.netv4.type == "IP_RANGE"
    assert events.netv6.type == "IP_RANGE"
    assert events.domain.type == "DNS_NAME"
    assert "domain" in events.domain.tags
    assert events.subdomain.type == "DNS_NAME"
    assert "subdomain" in events.subdomain.tags
    assert events.open_port.type == "OPEN_TCP_PORT"
    assert events.url_unverified.type == "URL_UNVERIFIED"
    assert events.ipv4_url_unverified.type == "URL_UNVERIFIED"
    assert events.ipv6_url_unverified.type == "URL_UNVERIFIED"
    assert "" not in events.ipv4
    assert None not in events.ipv4
    assert 1 not in events.ipv4
    assert False not in events.ipv4

    # ip tests
    assert events.ipv4 == scan.make_event("8.8.8.8", dummy=True)
    assert "8.8.8.8" in events.ipv4
    assert "8.8.8.8" == events.ipv4
    assert "8.8.8.8" in events.netv4
    assert "8.8.8.9" not in events.ipv4
    assert "8.8.9.8" not in events.netv4
    assert "8.8.8.8/31" in events.netv4
    assert "8.8.8.8/30" in events.netv4
    assert "8.8.8.8/29" not in events.netv4
    assert "2001:4860:4860::8888" in events.ipv6
    assert "2001:4860:4860::8888" in events.netv6
    assert "2001:4860:4860::8889" not in events.ipv6
    assert "2002:4860:4860::8888" not in events.netv6
    assert "2001:4860:4860::8888/127" in events.netv6
    assert "2001:4860:4860::8888/126" in events.netv6
    assert "2001:4860:4860::8888/125" not in events.netv6
    assert events.emoji not in events.ipv4
    assert events.emoji not in events.netv6
    assert events.netv6 not in events.emoji
    assert "dead::c0de" == scan.make_event(" [DEaD::c0De]:88", "DNS_NAME", dummy=True)

    # hostname tests
    assert events.domain.host == "publicapis.org"
    assert events.subdomain.host == "api.publicapis.org"
    assert events.domain.host_stem == "publicapis"
    assert events.subdomain.host_stem == "api.publicapis"
    assert "api.publicapis.org" in events.domain
    assert "api.publicapis.org" in events.subdomain
    assert "fsocie.ty" not in events.domain
    assert "fsocie.ty" not in events.subdomain
    assert events.subdomain in events.domain
    assert events.domain not in events.subdomain
    assert not events.ipv4 in events.domain
    assert not events.netv6 in events.domain
    assert events.emoji not in events.domain
    assert events.domain not in events.emoji
    assert "evilcorp.com" == scan.make_event(" eViLcorp.COM.:88", "DNS_NAME", dummy=True)
    assert "evilcorp.com" == scan.make_event("evilcorp.com.", "DNS_NAME", dummy=True)

    # url tests
    assert scan.make_event("http://evilcorp.com", dummy=True) == scan.make_event("http://evilcorp.com/", dummy=True)
    assert events.url_unverified.host == "api.publicapis.org"
    assert events.url_unverified in events.domain
    assert events.url_unverified in events.subdomain
    assert "api.publicapis.org:443" in events.url_unverified
    assert "publicapis.org" not in events.url_unverified
    assert events.ipv4_url_unverified in events.ipv4
    assert events.ipv4_url_unverified in events.netv4
    assert events.ipv6_url_unverified in events.ipv6
    assert events.ipv6_url_unverified in events.netv6
    assert events.emoji not in events.url_unverified
    assert events.emoji not in events.ipv6_url_unverified
    assert events.url_unverified not in events.emoji
    assert "https://evilcorp.com" == scan.make_event("https://evilcorp.com:443", dummy=True)
    assert "http://evilcorp.com" == scan.make_event("http://evilcorp.com:80", dummy=True)
    assert "http://evilcorp.com:80/asdf.js" in scan.make_event("http://evilcorp.com/asdf.js", dummy=True)
    assert "http://evilcorp.com/asdf.js" in scan.make_event("http://evilcorp.com:80/asdf.js", dummy=True)
    assert "https://evilcorp.com:443" == scan.make_event("https://evilcorp.com", dummy=True)
    assert "http://evilcorp.com:80" == scan.make_event("http://evilcorp.com", dummy=True)
    assert "https://evilcorp.com:80" == scan.make_event("https://evilcorp.com:80", dummy=True)
    assert "http://evilcorp.com:443" == scan.make_event("http://evilcorp.com:443", dummy=True)
    assert scan.make_event("https://evilcorp.com", dummy=True).with_port().geturl() == "https://evilcorp.com:443/"
    assert scan.make_event("https://evilcorp.com:666", dummy=True).with_port().geturl() == "https://evilcorp.com:666/"
    assert scan.make_event("https://evilcorp.com.:666", dummy=True) == "https://evilcorp.com:666/"
    assert scan.make_event("https://[bad::c0de]", dummy=True).with_port().geturl() == "https://[bad::c0de]:443/"
    assert scan.make_event("https://[bad::c0de]:666", dummy=True).with_port().geturl() == "https://[bad::c0de]:666/"
    url_event = scan.make_event("https://evilcorp.com", "URL", events.ipv4_url, tags=["status-200"])
    assert "status-200" in url_event.tags
    assert url_event.http_status == 200
    with pytest.raises(ValidationError, match=".*status tag.*"):
        scan.make_event("https://evilcorp.com", "URL", events.ipv4_url)

    # http response
    assert events.http_response.host == "example.com"
    assert events.http_response.port == 80
    assert events.http_response.parsed.scheme == "http"
    assert events.http_response.with_port().geturl() == "http://example.com:80/"

    http_response = scan.make_event(
        {
            "port": "80",
            "title": "HTTP%20RESPONSE",
            "url": "http://www.evilcorp.com:80",
            "input": "http://www.evilcorp.com:80",
            "location": "/asdf",
            "status_code": 301,
        },
        "HTTP_RESPONSE",
        dummy=True,
    )
    assert http_response.http_status == 301
    assert http_response.http_title == "HTTP RESPONSE"
    assert http_response.redirect_location == "http://www.evilcorp.com/asdf"

    # open port tests
    assert events.open_port in events.domain
    assert "api.publicapis.org:443" in events.open_port
    assert "bad.publicapis.org:443" not in events.open_port
    assert "publicapis.org:443" not in events.open_port
    assert events.ipv4_open_port in events.ipv4
    assert events.ipv4_open_port in events.netv4
    assert "8.8.8.9" not in events.ipv4_open_port
    assert events.ipv6_open_port in events.ipv6
    assert events.ipv6_open_port in events.netv6
    assert "2002:4860:4860::8888" not in events.ipv6_open_port
    assert events.emoji not in events.ipv6_open_port
    assert events.ipv6_open_port not in events.emoji

    # attribute tests
    assert events.ipv4.host == ipaddress.ip_address("8.8.8.8")
    assert events.ipv4.port is None
    assert events.ipv6.host == ipaddress.ip_address("2001:4860:4860::8888")
    assert events.ipv6.port is None
    assert events.domain.port is None
    assert events.subdomain.port is None
    assert events.open_port.host == "api.publicapis.org"
    assert events.open_port.port == 443
    assert events.ipv4_open_port.host == ipaddress.ip_address("8.8.8.8")
    assert events.ipv4_open_port.port == 443
    assert events.ipv6_open_port.host == ipaddress.ip_address("2001:4860:4860::8888")
    assert events.ipv6_open_port.port == 443
    assert events.url_unverified.host == "api.publicapis.org"
    assert events.url_unverified.port == 443
    assert events.ipv4_url_unverified.host == ipaddress.ip_address("8.8.8.8")
    assert events.ipv4_url_unverified.port == 443
    assert events.ipv6_url_unverified.host == ipaddress.ip_address("2001:4860:4860::8888")
    assert events.ipv6_url_unverified.port == 443

    javascript_event = scan.make_event("http://evilcorp.com/asdf/a.js?b=c#d", "URL_UNVERIFIED", dummy=True)
    assert "extension-js" in javascript_event.tags
    assert "httpx-only" in javascript_event.tags

    # scope distance
    event1 = scan.make_event("1.2.3.4", dummy=True)
    assert event1._scope_distance == -1
    event1.scope_distance = 0
    assert event1._scope_distance == 0
    event2 = scan.make_event("2.3.4.5", source=event1)
    assert event2._scope_distance == 1
    event3 = scan.make_event("3.4.5.6", source=event2)
    assert event3._scope_distance == 2
    event4 = scan.make_event("3.4.5.6", source=event3)
    assert event4._scope_distance == 2
    event5 = scan.make_event("4.5.6.7", source=event4)
    assert event5._scope_distance == 3

    url_1 = scan.make_event("https://127.0.0.1/asdf", "URL_UNVERIFIED", source=scan.root_event)
    assert url_1.scope_distance == 1
    url_2 = scan.make_event("https://127.0.0.1/test", "URL_UNVERIFIED", source=url_1)
    assert url_2.scope_distance == 1
    url_3 = scan.make_event("https://127.0.0.2/asdf", "URL_UNVERIFIED", source=url_1)
    assert url_3.scope_distance == 2

    org_stub_1 = scan.make_event("STUB1", "ORG_STUB", source=scan.root_event)
    org_stub_1.scope_distance == 1
    org_stub_2 = scan.make_event("STUB2", "ORG_STUB", source=org_stub_1)
    org_stub_2.scope_distance == 2

    # internal event tracking
    root_event = scan.make_event("0.0.0.0", dummy=True)
    internal_event1 = scan.make_event("1.2.3.4", source=root_event, internal=True)
    assert internal_event1._internal == True
    assert "internal" in internal_event1.tags

    # tag inheritance
    for tag in ("affiliate", "mutation-1"):
        affiliate_event = scan.make_event("1.2.3.4", source=root_event, tags=tag)
        assert tag in affiliate_event.tags
        affiliate_event2 = scan.make_event("1.2.3.4:88", source=affiliate_event)
        affiliate_event3 = scan.make_event("4.3.2.1:88", source=affiliate_event)
        assert tag in affiliate_event2.tags
        assert tag not in affiliate_event3.tags

    # event sorting
    parent1 = scan.make_event("127.0.0.1", source=scan.root_event)
    parent2 = scan.make_event("127.0.0.1", source=scan.root_event)
    parent2_child1 = scan.make_event("127.0.0.1", source=parent2)
    parent1_child1 = scan.make_event("127.0.0.1", source=parent1)
    parent1_child2 = scan.make_event("127.0.0.1", source=parent1)
    parent1_child2_child1 = scan.make_event("127.0.0.1", source=parent1_child2)
    parent1_child2_child2 = scan.make_event("127.0.0.1", source=parent1_child2)
    parent1_child1_child1 = scan.make_event("127.0.0.1", source=parent1_child1)
    parent2_child2 = scan.make_event("127.0.0.1", source=parent2)
    parent1_child2_child1_child1 = scan.make_event("127.0.0.1", source=parent1_child2_child1)

    sortable_events = {
        "parent1": parent1,
        "parent2": parent2,
        "parent2_child1": parent2_child1,
        "parent1_child1": parent1_child1,
        "parent1_child2": parent1_child2,
        "parent1_child2_child1": parent1_child2_child1,
        "parent1_child2_child2": parent1_child2_child2,
        "parent1_child1_child1": parent1_child1_child1,
        "parent2_child2": parent2_child2,
        "parent1_child2_child1_child1": parent1_child2_child1_child1,
    }

    ordered_list = [
        parent1,
        parent1_child1,
        parent1_child1_child1,
        parent1_child2,
        parent1_child2_child1,
        parent1_child2_child1_child1,
        parent1_child2_child2,
        parent2,
        parent2_child1,
        parent2_child2,
    ]

    shuffled_list = list(sortable_events.values())
    random.shuffle(shuffled_list)

    sorted_events = sorted(shuffled_list)
    assert sorted_events == ordered_list

    # test validation
    corrected_event1 = scan.make_event("asdf@asdf.com", "DNS_NAME", dummy=True)
    assert corrected_event1.type == "EMAIL_ADDRESS"
    corrected_event2 = scan.make_event("127.0.0.1", "DNS_NAME", dummy=True)
    assert corrected_event2.type == "IP_ADDRESS"
    corrected_event3 = scan.make_event("wat.asdf.com", "IP_ADDRESS", dummy=True)
    assert corrected_event3.type == "DNS_NAME"

    corrected_event4 = scan.make_event("bob@evilcorp.com", "USERNAME", dummy=True)
    assert corrected_event4.type == "EMAIL_ADDRESS"
    assert "affiliate" in corrected_event4.tags

    test_vuln = scan.make_event(
        {"host": "EVILcorp.com", "severity": "iNfo ", "description": "asdf"}, "VULNERABILITY", dummy=True
    )
    assert test_vuln.data["host"] == "evilcorp.com"
    assert test_vuln.data["severity"] == "INFO"
    test_vuln2 = scan.make_event(
        {"host": "192.168.1.1", "severity": "iNfo ", "description": "asdf"}, "VULNERABILITY", dummy=True
    )
    assert json.loads(test_vuln2.data_human)["severity"] == "INFO"
    assert test_vuln2.host.is_private
    with pytest.raises(ValidationError, match=".*validation error.*\nseverity\n.*Field required.*"):
        test_vuln = scan.make_event({"host": "evilcorp.com", "description": "asdf"}, "VULNERABILITY", dummy=True)
    with pytest.raises(ValidationError, match=".*host.*\n.*Invalid host.*"):
        test_vuln = scan.make_event(
            {"host": "!@#$", "severity": "INFO", "description": "asdf"}, "VULNERABILITY", dummy=True
        )
    with pytest.raises(ValidationError, match=".*severity.*\n.*Invalid severity.*"):
        test_vuln = scan.make_event(
            {"host": "evilcorp.com", "severity": "WACK", "description": "asdf"}, "VULNERABILITY", dummy=True
        )

    # punycode - event type detection

    # japanese
    assert scan.make_event("ドメイン.テスト", dummy=True).type == "DNS_NAME"
    assert scan.make_event("bob@ドメイン.テスト", dummy=True).type == "EMAIL_ADDRESS"
    assert scan.make_event("テスト@ドメイン.テスト", dummy=True).type == "EMAIL_ADDRESS"
    assert scan.make_event("ドメイン.テスト:80", dummy=True).type == "OPEN_TCP_PORT"
    assert scan.make_event("http://ドメイン.テスト:80", dummy=True).type == "URL_UNVERIFIED"
    assert scan.make_event("http://ドメイン.テスト:80/テスト", dummy=True).type == "URL_UNVERIFIED"

    assert scan.make_event("xn--eckwd4c7c.xn--zckzah", dummy=True).type == "DNS_NAME"
    assert scan.make_event("bob@xn--eckwd4c7c.xn--zckzah", dummy=True).type == "EMAIL_ADDRESS"
    assert scan.make_event("テスト@xn--eckwd4c7c.xn--zckzah", dummy=True).type == "EMAIL_ADDRESS"
    assert scan.make_event("xn--eckwd4c7c.xn--zckzah:80", dummy=True).type == "OPEN_TCP_PORT"
    assert scan.make_event("http://xn--eckwd4c7c.xn--zckzah:80", dummy=True).type == "URL_UNVERIFIED"
    assert scan.make_event("http://xn--eckwd4c7c.xn--zckzah:80/テスト", dummy=True).type == "URL_UNVERIFIED"

    # thai
    assert scan.make_event("เราเที่ยวด้วยกัน.com", dummy=True).type == "DNS_NAME"
    assert scan.make_event("bob@เราเที่ยวด้วยกัน.com", dummy=True).type == "EMAIL_ADDRESS"
    assert scan.make_event("ทดสอบ@เราเที่ยวด้วยกัน.com", dummy=True).type == "EMAIL_ADDRESS"
    assert scan.make_event("เราเที่ยวด้วยกัน.com:80", dummy=True).type == "OPEN_TCP_PORT"
    assert scan.make_event("http://เราเที่ยวด้วยกัน.com:80", dummy=True).type == "URL_UNVERIFIED"
    assert scan.make_event("http://เราเที่ยวด้วยกัน.com:80/ทดสอบ", dummy=True).type == "URL_UNVERIFIED"

    assert scan.make_event("xn--12c1bik6bbd8ab6hd1b5jc6jta.com", dummy=True).type == "DNS_NAME"
    assert scan.make_event("bob@xn--12c1bik6bbd8ab6hd1b5jc6jta.com", dummy=True).type == "EMAIL_ADDRESS"
    assert scan.make_event("ทดสอบ@xn--12c1bik6bbd8ab6hd1b5jc6jta.com", dummy=True).type == "EMAIL_ADDRESS"
    assert scan.make_event("xn--12c1bik6bbd8ab6hd1b5jc6jta.com:80", dummy=True).type == "OPEN_TCP_PORT"
    assert scan.make_event("http://xn--12c1bik6bbd8ab6hd1b5jc6jta.com:80", dummy=True).type == "URL_UNVERIFIED"
    assert scan.make_event("http://xn--12c1bik6bbd8ab6hd1b5jc6jta.com:80/ทดสอบ", dummy=True).type == "URL_UNVERIFIED"

    # punycode - encoding / decoding tests

    # japanese
    assert scan.make_event("xn--eckwd4c7c.xn--zckzah", dummy=True).data == "xn--eckwd4c7c.xn--zckzah"
    assert scan.make_event("bob@xn--eckwd4c7c.xn--zckzah", dummy=True).data == "bob@xn--eckwd4c7c.xn--zckzah"
    assert scan.make_event("テスト@xn--eckwd4c7c.xn--zckzah", dummy=True).data == "テスト@xn--eckwd4c7c.xn--zckzah"
    assert scan.make_event("xn--eckwd4c7c.xn--zckzah:80", dummy=True).data == "xn--eckwd4c7c.xn--zckzah:80"
    assert scan.make_event("http://xn--eckwd4c7c.xn--zckzah:80", dummy=True).data == "http://xn--eckwd4c7c.xn--zckzah/"
    assert (
        scan.make_event("http://xn--eckwd4c7c.xn--zckzah:80/テスト", dummy=True).data
        == "http://xn--eckwd4c7c.xn--zckzah/テスト"
    )

    assert scan.make_event("ドメイン.テスト", dummy=True).data == "xn--eckwd4c7c.xn--zckzah"
    assert scan.make_event("bob@ドメイン.テスト", dummy=True).data == "bob@xn--eckwd4c7c.xn--zckzah"
    assert scan.make_event("テスト@ドメイン.テスト", dummy=True).data == "テスト@xn--eckwd4c7c.xn--zckzah"
    assert scan.make_event("ドメイン.テスト:80", dummy=True).data == "xn--eckwd4c7c.xn--zckzah:80"
    assert scan.make_event("http://ドメイン.テスト:80", dummy=True).data == "http://xn--eckwd4c7c.xn--zckzah/"
    assert (
        scan.make_event("http://ドメイン.テスト:80/テスト", dummy=True).data
        == "http://xn--eckwd4c7c.xn--zckzah/テスト"
    )
    # thai
    assert (
        scan.make_event("xn--12c1bik6bbd8ab6hd1b5jc6jta.com", dummy=True).data == "xn--12c1bik6bbd8ab6hd1b5jc6jta.com"
    )
    assert (
        scan.make_event("bob@xn--12c1bik6bbd8ab6hd1b5jc6jta.com", dummy=True).data
        == "bob@xn--12c1bik6bbd8ab6hd1b5jc6jta.com"
    )
    assert (
        scan.make_event("ทดสอบ@xn--12c1bik6bbd8ab6hd1b5jc6jta.com", dummy=True).data
        == "ทดสอบ@xn--12c1bik6bbd8ab6hd1b5jc6jta.com"
    )
    assert (
        scan.make_event("xn--12c1bik6bbd8ab6hd1b5jc6jta.com:80", dummy=True).data
        == "xn--12c1bik6bbd8ab6hd1b5jc6jta.com:80"
    )
    assert (
        scan.make_event("http://xn--12c1bik6bbd8ab6hd1b5jc6jta.com:80", dummy=True).data
        == "http://xn--12c1bik6bbd8ab6hd1b5jc6jta.com/"
    )
    assert (
        scan.make_event("http://xn--12c1bik6bbd8ab6hd1b5jc6jta.com:80/ทดสอบ", dummy=True).data
        == "http://xn--12c1bik6bbd8ab6hd1b5jc6jta.com/ทดสอบ"
    )

    assert scan.make_event("เราเที่ยวด้วยกัน.com", dummy=True).data == "xn--12c1bik6bbd8ab6hd1b5jc6jta.com"
    assert scan.make_event("bob@เราเที่ยวด้วยกัน.com", dummy=True).data == "bob@xn--12c1bik6bbd8ab6hd1b5jc6jta.com"
    assert scan.make_event("ทดสอบ@เราเที่ยวด้วยกัน.com", dummy=True).data == "ทดสอบ@xn--12c1bik6bbd8ab6hd1b5jc6jta.com"
    assert scan.make_event("เราเที่ยวด้วยกัน.com:80", dummy=True).data == "xn--12c1bik6bbd8ab6hd1b5jc6jta.com:80"
    assert (
        scan.make_event("http://เราเที่ยวด้วยกัน.com:80", dummy=True).data == "http://xn--12c1bik6bbd8ab6hd1b5jc6jta.com/"
    )
    assert (
        scan.make_event("http://เราเที่ยวด้วยกัน.com:80/ทดสอบ", dummy=True).data
        == "http://xn--12c1bik6bbd8ab6hd1b5jc6jta.com/ทดสอบ"
    )

    # test event serialization
    from bbot.core.event import event_from_json

    db_event = scan.make_event("evilcorp.com", dummy=True)
    db_event._resolved_hosts = {"127.0.0.1"}
    db_event.scope_distance = 1
    timestamp = db_event.timestamp.timestamp()
    json_event = db_event.json()
    assert json_event["scope_distance"] == 1
    assert json_event["data"] == "evilcorp.com"
    assert json_event["type"] == "DNS_NAME"
    assert json_event["timestamp"] == timestamp
    reconstituted_event = event_from_json(json_event)
    assert reconstituted_event.scope_distance == 1
    assert reconstituted_event.timestamp.timestamp() == timestamp
    assert reconstituted_event.data == "evilcorp.com"
    assert reconstituted_event.type == "DNS_NAME"
    assert "127.0.0.1" in reconstituted_event.resolved_hosts

    http_response = scan.make_event(httpx_response, "HTTP_RESPONSE", source=scan.root_event)
    assert http_response.source_id == scan.root_event.id
    assert http_response.data["input"] == "http://example.com:80"
    json_event = http_response.json(mode="graph")
    assert isinstance(json_event["data"], str)
    json_event = http_response.json()
    assert isinstance(json_event["data"], dict)
    assert json_event["type"] == "HTTP_RESPONSE"
    assert json_event["source"] == scan.root_event.id
    reconstituted_event = event_from_json(json_event)
    assert isinstance(reconstituted_event.data, dict)
    assert reconstituted_event.data["input"] == "http://example.com:80"
    assert reconstituted_event.type == "HTTP_RESPONSE"
    assert reconstituted_event.source_id == scan.root_event.id

    event_1 = scan.make_event("127.0.0.1", source=scan.root_event)
    event_2 = scan.make_event("127.0.0.2", source=event_1)
    event_3 = scan.make_event("127.0.0.3", source=event_2)
    event_3._omit = True
    event_4 = scan.make_event("127.0.0.4", source=event_3)
    event_5 = scan.make_event("127.0.0.5", source=event_4)
    assert event_5.get_sources() == [event_4, event_3, event_2, event_1, scan.root_event]
    assert event_5.get_sources(omit=True) == [event_4, event_2, event_1, scan.root_event]
