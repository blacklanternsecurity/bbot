import os
import sys
import json
import logging
import ipaddress
from time import sleep

import bbot.core.logger  # noqa: F401
from bbot.core.errors import *
from .bbot_fixtures import *  # noqa: F401
from bbot.modules import module_loader

log = logging.getLogger(f"bbot.test")

# silence stdout
root_logger = logging.getLogger()
for h in root_logger.handlers:
    h.addFilter(lambda x: x.levelno != 100)

os.environ["BBOT_SUDO_PASS"] = "nah"

available_modules = list(module_loader.configs(type="scan"))
available_output_modules = list(module_loader.configs(type="output"))


def test_events(events, scan, helpers, bbot_config):

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
    assert scan.make_event("https://[bad::c0de]", dummy=True).with_port().geturl() == "https://[bad::c0de]:443/"
    assert scan.make_event("https://[bad::c0de]:666", dummy=True).with_port().geturl() == "https://[bad::c0de]:666/"
    assert "status-200" in scan.make_event("https://evilcorp.com", "URL", events.ipv4_url, tags=["status-200"]).tags
    with pytest.raises(ValidationError, match=".*status tag.*"):
        scan.make_event("https://evilcorp.com", "URL", events.ipv4_url)

    # http response
    assert events.http_response.host == "example.com"
    assert events.http_response.port == 80
    assert events.http_response.parsed.scheme == "http"
    assert events.http_response.with_port().geturl() == "http://example.com:80/"

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
    event1.make_in_scope()
    assert event1._scope_distance == 0
    event2 = scan.make_event("2.3.4.5", source=event1)
    assert event2._scope_distance == 1
    event3 = scan.make_event("3.4.5.6", source=event2)
    assert event3._scope_distance == 2

    # internal event tracking
    root_event = scan.make_event("0.0.0.0", dummy=True)
    internal_event1 = scan.make_event("1.2.3.4", source=root_event, internal=True)
    assert internal_event1._internal == True
    assert internal_event1._made_internal == True
    internal_event1.make_in_scope()
    assert internal_event1._internal == False
    assert internal_event1._made_internal == False
    internal_event2 = scan.make_event("2.3.4.5", source=internal_event1, internal=True)
    internal_event3 = scan.make_event("3.4.5.6", source=internal_event2, internal=True)
    internal_event4 = scan.make_event("4.5.6.7", source=internal_event3)
    source_trail = internal_event4.make_in_scope()
    assert internal_event4._internal == False
    assert internal_event3._internal == False
    assert internal_event2._internal == False
    assert len(source_trail) == 2
    assert internal_event2 in source_trail
    assert internal_event3 in source_trail

    # event sorting
    sort1 = scan.make_event("127.0.0.1", dummy=True)
    sort1._priority = 1
    sort2 = scan.make_event("127.0.0.1", dummy=True)
    sort2._priority = 2
    sort3 = scan.make_event("127.0.0.1", dummy=True)
    sort3._priority = 3
    mod1 = helpers._make_dummy_module(name="MOD1", _type="ASDF")
    mod1._priority = 1
    mod2 = helpers._make_dummy_module(name="MOD2", _type="ASDF")
    mod2._priority = 2
    mod3 = helpers._make_dummy_module(name="MOD3", _type="ASDF")
    mod3._priority = 3
    sort1.module = mod1
    sort2.module = mod2
    sort3.module = mod3
    assert 2 < sort1.priority < 2.01
    assert sort1 < sort2
    assert sort1 < sort3
    assert 4 < sort2.priority < 4.01
    assert sort2 > sort1
    assert sort2 < sort3
    assert 6 < sort3.priority < 6.01
    assert sort3 > sort1
    assert sort3 > sort2
    assert tuple(sorted([sort3, sort2, sort1])) == (sort1, sort2, sort3)

    # test validation
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
    with pytest.raises(ValidationError, match=".*severity.*\n.*field required.*"):
        test_vuln = scan.make_event({"host": "evilcorp.com", "description": "asdf"}, "VULNERABILITY", dummy=True)
    with pytest.raises(ValidationError, match=".*host.*\n.*Invalid host.*"):
        test_vuln = scan.make_event(
            {"host": "!@#$", "severity": "INFO", "description": "asdf"}, "VULNERABILITY", dummy=True
        )
    with pytest.raises(ValidationError, match=".*severity.*\n.*Invalid severity.*"):
        test_vuln = scan.make_event(
            {"host": "evilcorp.com", "severity": "WACK", "description": "asdf"}, "VULNERABILITY", dummy=True
        )


def test_manager(bbot_config):
    from bbot.scanner import Scanner

    # test _emit_event
    results = []
    success_callback = lambda e: results.append("success")
    scan1 = Scanner("127.0.0.1", config=bbot_config)
    scan1.status = "RUNNING"
    scan1.manager.queue_event = lambda e: results.append(e)
    manager = scan1.manager
    localhost = scan1.make_event("127.0.0.1", source=scan1.root_event)

    class DummyModule1:
        _type = "output"
        suppress_dupes = True

    class DummyModule2:
        _type = "DNS"
        suppress_dupes = True

    localhost.module = DummyModule1()
    # test abort_if
    manager._emit_event(localhost, abort_if=lambda e: e.module._type == "output")
    assert len(results) == 0
    manager._emit_event(
        localhost, on_success_callback=success_callback, abort_if=lambda e: e.module._type == "plumbus"
    )
    assert localhost in results
    assert "success" in results
    results.clear()
    # test deduplication
    manager._emit_event(localhost, on_success_callback=success_callback)
    assert len(results) == 0
    # test dns resolution
    googledns = scan1.make_event("8.8.8.8", source=scan1.root_event)
    googledns.module = DummyModule2()
    googledns.source = "asdf"
    googledns.make_in_scope()
    event_children = []
    manager.emit_event = lambda e, *args, **kwargs: event_children.append(e)
    manager._emit_event(googledns)
    assert len(event_children) > 0
    assert googledns in results
    results.clear()
    event_children.clear()
    # same dns event
    manager._emit_event(googledns)
    assert len(results) == 0
    assert len(event_children) == 0
    # same dns event but with _force_output
    googledns._force_output = True
    manager._emit_event(googledns)
    assert googledns in results
    assert len(event_children) == 0
    googledns._force_output = False
    results.clear()
    # same dns event but different source
    googledns.source_id = "fdsa"
    manager._emit_event(googledns)
    assert len(event_children) == 0
    assert googledns in results

    # event filtering based on scope_distance
    output_queue = []
    module_queue = []
    manager_queue = []
    scan1 = Scanner("127.0.0.1", modules=["ipneighbor"], output_modules=["json"], config=bbot_config)
    scan1.status = "RUNNING"
    scan1.load_modules()
    manager = scan1.manager
    test_event1 = scan1.make_event("1.2.3.4", source=scan1.root_event)
    test_event1.make_in_scope()
    test_event2 = scan1.make_event("2.3.4.5", source=test_event1)
    test_event3 = scan1.make_event("3.4.5.6", source=test_event2)

    scan1.manager.queue_event = lambda e: manager_queue.append(e)

    scan1.scope_search_distance = 1
    scan1.scope_report_distance = 0
    assert test_event1.scope_distance == 0
    manager._emit_event(test_event1)
    assert test_event1 in manager_queue
    assert test_event1._internal == False
    assert test_event2.scope_distance == 1
    manager._emit_event(test_event2)
    assert test_event2 in manager_queue
    assert test_event2._internal == True
    manager_queue.clear()
    manager.events_accepted.clear()

    scan1.modules["json"].queue_event = lambda e: output_queue.append(e)
    scan1.modules["ipneighbor"].queue_event = lambda e: module_queue.append(e)

    # in-scope event
    assert test_event1.scope_distance == 0
    manager.distribute_event(test_event1)
    assert hash(test_event1) in manager.events_distributed
    assert test_event1 in module_queue
    assert test_event1 in output_queue
    module_queue.clear()
    output_queue.clear()
    # duplicate event
    manager.distribute_event(test_event1)
    assert test_event1 not in module_queue
    assert test_event1 in output_queue
    module_queue.clear()
    output_queue.clear()
    manager.events_distributed.clear()
    # event.scope_distance == 1
    assert test_event2.scope_distance == 1
    manager.distribute_event(test_event2)
    assert test_event2 in module_queue
    assert test_event2 not in output_queue
    assert test_event2._internal == True
    assert test_event2._force_output == False
    assert scan1.modules["json"]._filter_event(test_event2) == False
    module_queue.clear()
    output_queue.clear()
    manager.events_distributed.clear()
    # event.scope_distance == 2
    assert test_event3.scope_distance == 2
    manager.distribute_event(test_event3)
    assert test_event3 not in module_queue
    assert test_event3 not in output_queue
    module_queue.clear()
    output_queue.clear()
    manager.events_distributed.clear()
    # event.scope_distance == 2 and _force_output == True
    test_event3._force_output = True
    assert test_event3.scope_distance == 2
    manager.distribute_event(test_event3)
    assert test_event3 not in module_queue
    assert test_event3 in output_queue


def test_curl(helpers):

    helpers.curl()
    helpers.curl(url="http://www.example.com", ignore_bbot_global_settings=True)
    helpers.curl(url="http://www.example.com", head_mode=True)
    helpers.curl(url="http://www.example.com", raw_body=True)
    helpers.curl(
        url="http://www.example.com",
        raw_path=True,
        headers={"test": "test", "test2": ["test2"]},
        ignore_bbot_global_settings=False,
        post_data={"test": "test"},
        method="POST",
        cookies={"test": "test"},
        path_override="/index.html",
    )


def test_helpers(patch_requests, patch_commands, helpers, scan):

    old_run, old_run_live = patch_commands
    request, download = patch_requests

    ### URL ###
    bad_urls = (
        "http://e.co/index.html",
        "http://e.co/u/1111/info",
        "http://e.co/u/2222/info",
        "http://e.co/u/3333/info",
        "http://e.co/u/4444/info",
        "http://e.co/u/5555/info",
    )
    new_urls = tuple(helpers.collapse_urls(bad_urls, threshold=4))
    assert len(new_urls) == 2
    new_urls = tuple(sorted([u.geturl() for u in helpers.collapse_urls(bad_urls, threshold=5)]))
    assert new_urls == bad_urls

    new_url = helpers.add_get_params("http://evilcorp.com/a?p=1&q=2", {"r": 3, "s": "asdf"}).geturl()
    query = dict(s.split("=") for s in new_url.split("?")[-1].split("&"))
    query = tuple(sorted(query.items(), key=lambda x: x[0]))
    assert query == (
        ("p", "1"),
        ("q", "2"),
        ("r", "3"),
        ("s", "asdf"),
    )
    assert tuple(sorted(helpers.get_get_params("http://evilcorp.com/a?p=1&q=2#frag").items())) == (
        ("p", ["1"]),
        ("q", ["2"]),
    )

    assert helpers.clean_url("http://evilcorp.com:80").geturl() == "http://evilcorp.com/"
    assert helpers.clean_url("http://evilcorp.com/asdf?a=asdf#frag").geturl() == "http://evilcorp.com/asdf"
    assert helpers.clean_url("http://evilcorp.com//asdf").geturl() == "http://evilcorp.com/asdf"

    assert helpers.url_depth("http://evilcorp.com/asdf/user/") == 2
    assert helpers.url_depth("http://evilcorp.com/asdf/user") == 2
    assert helpers.url_depth("http://evilcorp.com/asdf/") == 1
    assert helpers.url_depth("http://evilcorp.com/asdf") == 1
    assert helpers.url_depth("http://evilcorp.com/") == 0
    assert helpers.url_depth("http://evilcorp.com") == 0

    ### HTTP COMPARE ###
    compare_helper = helpers.http_compare("http://www.example.com")
    compare_helper.compare("http://www.example.com", headers={"asdf": "asdf"})
    compare_helper.compare("http://www.example.com", cookies={"asdf": "asdf"})
    compare_helper.compare("http://www.example.com", check_reflection=True)
    compare_helper.compare_body({"asdf": "fdsa"}, {"fdsa": "asdf"})
    for mode in ("getparam", "header", "cookie"):
        compare_helper.canary_check("http://www.example.com", mode=mode) == True

    ### MISC ###
    assert helpers.is_domain("evilcorp.co.uk")
    assert not helpers.is_domain("www.evilcorp.co.uk")
    assert helpers.is_subdomain("www.evilcorp.co.uk")
    assert not helpers.is_subdomain("evilcorp.co.uk")
    assert helpers.is_url("http://evilcorp.co.uk/asdf?a=b&c=d#asdf")
    assert helpers.is_url("https://evilcorp.co.uk/asdf?a=b&c=d#asdf")
    assert not helpers.is_url("https:/evilcorp.co.uk/asdf?a=b&c=d#asdf")
    assert not helpers.is_url("/evilcorp.co.uk/asdf?a=b&c=d#asdf")
    assert not helpers.is_url("ftp://evilcorp.co.uk")
    assert helpers.parent_domain("www.evilcorp.co.uk") == "evilcorp.co.uk"
    assert helpers.parent_domain("evilcorp.co.uk") == "evilcorp.co.uk"
    assert helpers.parent_domain("localhost") == "localhost"
    assert list(helpers.domain_parents("test.www.evilcorp.co.uk")) == ["www.evilcorp.co.uk", "evilcorp.co.uk"]
    assert list(helpers.domain_parents("www.evilcorp.co.uk", include_self=True)) == [
        "www.evilcorp.co.uk",
        "evilcorp.co.uk",
    ]
    assert list(helpers.domain_parents("evilcorp.co.uk", include_self=True)) == ["evilcorp.co.uk"]
    assert list(helpers.ip_network_parents("0.0.0.0/2")) == [
        ipaddress.ip_network("0.0.0.0/1"),
        ipaddress.ip_network("0.0.0.0/0"),
    ]
    assert list(helpers.ip_network_parents("0.0.0.0/1", include_self=True)) == [
        ipaddress.ip_network("0.0.0.0/1"),
        ipaddress.ip_network("0.0.0.0/0"),
    ]
    assert helpers.is_ip("127.0.0.1")
    assert not helpers.is_ip("127.0.0.0.1")

    assert helpers.domain_stem("evilcorp.co.uk") == "evilcorp"
    assert helpers.domain_stem("www.evilcorp.co.uk") == "www.evilcorp"

    assert helpers.host_in_host("www.evilcorp.com", "evilcorp.com") == True
    assert helpers.host_in_host("asdf.www.evilcorp.com", "evilcorp.com") == True
    assert helpers.host_in_host("evilcorp.com", "www.evilcorp.com") == False
    assert helpers.host_in_host("evilcorp.com", "evilcorp.com") == True
    assert helpers.host_in_host("evilcorp.com", "eevilcorp.com") == False
    assert helpers.host_in_host("eevilcorp.com", "evilcorp.com") == False
    assert helpers.host_in_host("evilcorp.com", "evilcorp") == False
    assert helpers.host_in_host("evilcorp", "evilcorp.com") == False
    assert helpers.host_in_host("evilcorp.com", "com") == True

    assert tuple(helpers.extract_emails("asdf@asdf.com\nT@t.Com&a=a@a.com__ b@b.com")) == (
        "asdf@asdf.com",
        "t@t.com",
        "a@a.com",
        "b@b.com",
    )

    assert helpers.split_host_port("https://evilcorp.co.uk") == ("evilcorp.co.uk", 443)
    assert helpers.split_host_port("http://evilcorp.co.uk:666") == ("evilcorp.co.uk", 666)
    assert helpers.split_host_port("evilcorp.co.uk:666") == ("evilcorp.co.uk", 666)
    assert helpers.split_host_port("evilcorp.co.uk") == ("evilcorp.co.uk", None)
    assert helpers.split_host_port("d://wat:wat") == ("wat", None)
    assert helpers.split_host_port("https://[dead::beef]:8338") == (ipaddress.ip_address("dead::beef"), 8338)
    extracted_words = helpers.extract_words("blacklanternsecurity")
    assert "black" in extracted_words
    # assert "blacklantern" in extracted_words
    # assert "lanternsecurity" in extracted_words
    # assert "blacklanternsecurity" in extracted_words
    assert "bls" in extracted_words
    ipv4_netloc = helpers.make_netloc("192.168.1.1", 80)
    assert ipv4_netloc == "192.168.1.1:80"
    ipv6_netloc = helpers.make_netloc("dead::beef", "443")
    assert ipv6_netloc == "[dead::beef]:443"

    assert helpers.get_file_extension("https://evilcorp.com/evilcorp.com/test/asdf.TXT") == "txt"
    assert helpers.get_file_extension("/etc/conf/test.tar.gz") == "gz"
    assert helpers.get_file_extension("/etc/passwd") == ""

    assert list(helpers.search_dict_by_key("asdf", {"asdf": "fdsa", 4: [{"asdf": 5}]})) == ["fdsa", 5]
    assert list(helpers.search_dict_by_key("asdf", {"wat": {"asdf": "fdsa"}})) == ["fdsa"]
    assert list(helpers.search_dict_by_key("asdf", [{"wat": {"nope": 1}}, {"wat": [{"asdf": "fdsa"}]}])) == ["fdsa"]
    assert not list(helpers.search_dict_by_key("asdf", [{"wat": {"nope": 1}}, {"wat": [{"fdsa": "asdf"}]}]))
    assert not list(helpers.search_dict_by_key("asdf", "asdf"))

    filtered_dict = helpers.filter_dict(
        {"modules": {"c99": {"api_key": "1234", "filterme": "asdf"}, "ipneighbor": {"test": "test"}}}, "api_key"
    )
    assert "api_key" in filtered_dict["modules"]["c99"]
    assert "filterme" not in filtered_dict["modules"]["c99"]
    assert "ipneighbor" not in filtered_dict["modules"]

    filtered_dict2 = helpers.filter_dict(
        {"modules": {"c99": {"api_key": "1234", "filterme": "asdf"}, "ipneighbor": {"test": "test"}}}, "c99"
    )
    assert "api_key" in filtered_dict2["modules"]["c99"]
    assert "filterme" in filtered_dict2["modules"]["c99"]
    assert "ipneighbor" not in filtered_dict2["modules"]

    filtered_dict3 = helpers.filter_dict(
        {"modules": {"c99": {"api_key": "1234", "filterme": "asdf"}, "ipneighbor": {"test": "test"}}},
        "key",
        fuzzy=True,
    )
    assert "api_key" in filtered_dict3["modules"]["c99"]
    assert "filterme" not in filtered_dict3["modules"]["c99"]
    assert "ipneighbor" not in filtered_dict3["modules"]

    cleaned_dict = helpers.clean_dict(
        {"modules": {"c99": {"api_key": "1234", "filterme": "asdf"}, "ipneighbor": {"test": "test"}}}, "api_key"
    )
    assert "api_key" not in cleaned_dict["modules"]["c99"]
    assert "filterme" in cleaned_dict["modules"]["c99"]
    assert "ipneighbor" in cleaned_dict["modules"]

    cleaned_dict2 = helpers.clean_dict(
        {"modules": {"c99": {"api_key": "1234", "filterme": "asdf"}, "ipneighbor": {"test": "test"}}}, "c99"
    )
    assert "c99" not in cleaned_dict2["modules"]
    assert "ipneighbor" in cleaned_dict2["modules"]

    cleaned_dict3 = helpers.clean_dict(
        {"modules": {"c99": {"api_key": "1234", "filterme": "asdf"}, "ipneighbor": {"test": "test"}}},
        "key",
        fuzzy=True,
    )
    assert "api_key" not in cleaned_dict3["modules"]["c99"]
    assert "filterme" in cleaned_dict3["modules"]["c99"]
    assert "ipneighbor" in cleaned_dict3["modules"]

    replaced = helpers.search_format_dict({"asdf": [{"wat": {"here": "{replaceme}!"}}, {500: True}]}, replaceme="asdf")
    assert replaced["asdf"][1][500] == True
    assert replaced["asdf"][0]["wat"]["here"] == "asdf!"

    assert helpers.split_list([1, 2, 3, 4, 5]) == [[1, 2], [3, 4, 5]]
    assert list(helpers.grouper("ABCDEFG", 3)) == [["A", "B", "C"], ["D", "E", "F"], ["G"]]

    assert len(helpers.rand_string(3)) == 3
    assert len(helpers.rand_string(1)) == 1
    assert len(helpers.rand_string(0)) == 0
    assert type(helpers.rand_string(0)) == str

    test_file = Path(scan.config["home"]) / "testfile.asdf"
    test_file.touch()

    assert test_file.is_file()
    backup = helpers.backup_file(test_file)
    assert backup.name == "testfile.1.asdf"
    assert not test_file.exists()
    assert backup.is_file()
    test_file.touch()
    backup2 = helpers.backup_file(test_file)
    assert backup2.name == "testfile.1.asdf"
    assert not test_file.exists()
    assert backup2.is_file()
    older_backup = Path(scan.config["home"]) / "testfile.2.asdf"
    assert older_backup.is_file()
    older_backup.unlink()
    backup.unlink()

    with open(test_file, "w") as f:
        f.write("asdf\nfdsa")

    assert "asdf" in helpers.str_or_file(str(test_file))
    assert "nope" in helpers.str_or_file("nope")
    assert tuple(helpers.chain_lists([str(test_file), "nope"], try_files=True)) == ("asdf", "fdsa", "nope")
    assert test_file.is_file()

    with pytest.raises(DirectoryCreationError, match="Failed to create.*"):
        helpers.mkdir(test_file)

    helpers._rm_at_exit(test_file)
    assert not test_file.exists()

    ### VALIDATORS ###
    # hosts
    assert helpers.validators.validate_host(" evilCorp.COM") == "evilcorp.com"
    assert helpers.validators.validate_host("LOCALHOST ") == "localhost"
    assert helpers.validators.validate_host(" 192.168.1.1") == "192.168.1.1"
    assert helpers.validators.validate_host(" Dead::c0dE ") == "dead::c0de"
    assert helpers.validators.soft_validate(" evilCorp.COM", "host") == True
    assert helpers.validators.soft_validate("!@#$", "host") == False
    with pytest.raises(ValueError):
        assert helpers.validators.validate_host("!@#$")
    # ports
    assert helpers.validators.validate_port(666) == 666
    assert helpers.validators.validate_port(666666) == 65535
    assert helpers.validators.soft_validate(666, "port") == True
    assert helpers.validators.soft_validate("!@#$", "port") == False
    with pytest.raises(ValueError):
        helpers.validators.validate_port("asdf")
    # urls
    assert helpers.validators.validate_url(" httP://evilcorP.com/asdf?a=b&c=d#e") == "http://evilcorp.com/asdf"
    assert (
        helpers.validators.validate_url_parsed(" httP://evilcorP.com/asdf?a=b&c=d#e").geturl()
        == "http://evilcorp.com/asdf"
    )
    assert helpers.validators.soft_validate(" httP://evilcorP.com/asdf?a=b&c=d#e", "url") == True
    assert helpers.validators.soft_validate("!@#$", "url") == False
    with pytest.raises(ValueError):
        helpers.validators.validate_url("!@#$")
    # severities
    assert helpers.validators.validate_severity(" iNfo") == "INFO"
    assert helpers.validators.soft_validate(" iNfo", "severity") == True
    assert helpers.validators.soft_validate("NOPE", "severity") == False
    with pytest.raises(ValueError):
        helpers.validators.validate_severity("NOPE")
    # emails
    assert helpers.validators.validate_email(" bOb@eViLcorp.COM") == "bob@evilcorp.com"
    assert helpers.validators.soft_validate(" bOb@eViLcorp.COM", "email") == True
    assert helpers.validators.soft_validate("!@#$", "email") == False
    with pytest.raises(ValueError):
        helpers.validators.validate_email("!@#$")

    assert type(helpers.make_date()) == str

    def raise_filenotfound():
        raise FileNotFoundError("asdf")

    def raise_brokenpipe():
        raise BrokenPipeError("asdf")

    from bbot.core.helpers import command

    command.catch(raise_filenotfound)
    command.catch(raise_brokenpipe)

    ### COMMAND ###
    assert "plumbus\n" in old_run(helpers, ["echo", "plumbus"], text=True).stdout
    assert "plumbus\n" in list(old_run_live(helpers, ["echo", "plumbus"]))
    expected_output = ["lumbus\n", "plumbus\n", "rumbus\n"]
    assert list(old_run_live(helpers, ["cat"], input="lumbus\nplumbus\nrumbus")) == expected_output

    def plumbus_generator():
        yield "lumbus"
        yield "plumbus"

    assert "plumbus\n" in list(old_run_live(helpers, ["cat"], input=plumbus_generator()))
    tempfile = helpers.tempfile(("lumbus", "plumbus"), pipe=True)
    with open(tempfile) as f:
        assert "plumbus\n" in list(f)
    tempfile = helpers.tempfile(("lumbus", "plumbus"), pipe=False)
    with open(tempfile) as f:
        assert "plumbus\n" in list(f)

    ### CACHE ###
    helpers.cache_put("string", "wat")
    helpers.cache_put("binary", b"wat")
    assert helpers.cache_get("string") == "wat"
    assert helpers.cache_get("binary") == "wat"
    assert helpers.cache_get("binary", text=False) == b"wat"
    cache_filename = helpers.cache_filename("string")
    (m, i, d, n, u, g, sz, atime, mtime, ctime) = os.stat(str(cache_filename))
    # change modified time to be 10 days in the past
    os.utime(str(cache_filename), times=(atime, mtime - (3600 * 24 * 10)))
    assert helpers.cache_get("string", cache_hrs=24 * 7) is None
    assert helpers.cache_get("string", cache_hrs=24 * 14) == "wat"

    cache_dict = helpers.CacheDict(max_size=10)
    cache_dict.put("1", 2)
    assert cache_dict["1"] == 2
    assert cache_dict.get("1") == 2
    assert len(cache_dict) == 1
    cache_dict["2"] = 3
    assert cache_dict["2"] == 3
    assert cache_dict.get("2") == 3
    assert len(cache_dict) == 2
    for i in range(20):
        cache_dict[str(i)] = i + 1
    assert len(cache_dict) == 10
    assert tuple(cache_dict) == tuple(hash(str(x)) for x in range(10, 20))

    ### WEB ###
    assert getattr(request(helpers, "https://api.publicapis.org/health"), "text", "").startswith("{")
    assert getattr(request(helpers, "https://api.publicapis.org/health", cache_for=60), "text", "").startswith("{")
    filename = download(helpers, "https://api.publicapis.org/health", cache_hrs=1)
    assert Path(str(filename)).is_file()
    assert helpers.is_cached("https://api.publicapis.org/health")

    assert helpers.wordlist("https://api.publicapis.org/healthasdf").is_file()
    test_file = Path(scan.config["home"]) / "testfile.asdf"
    with open(test_file, "w") as f:
        for i in range(100):
            f.write(f"{i}\n")
    assert len(list(open(test_file).readlines())) == 100
    assert helpers.wordlist(test_file).is_file()
    truncated_file = helpers.wordlist(test_file, lines=10)
    assert truncated_file.is_file()
    assert len(list(open(truncated_file).readlines())) == 10
    with pytest.raises(WordlistError):
        helpers.wordlist("/tmp/a9pseoysadf/asdkgjaosidf")
    test_file.unlink()

    ### DNS ###
    # resolution
    assert all([helpers.is_ip(i) for i in helpers.resolve("scanme.nmap.org")])
    assert "dns.google" in helpers.resolve("8.8.8.8")
    assert "dns.google" in helpers.resolve("2001:4860:4860::8888")
    resolved_ips = helpers.resolve("dns.google")
    assert "2001:4860:4860::8888" in resolved_ips
    assert "8.8.8.8" in resolved_ips
    assert any([helpers.is_subdomain(h) for h in helpers.resolve("google.com", type="mx")])
    v6_ips = helpers.resolve("www.google.com", type="AAAA")
    assert all([i.version == 6 for i in [ipaddress.ip_address(_) for _ in v6_ips]])
    assert not helpers.resolve(f"{helpers.rand_string(length=30)}.com")
    # batch resolution
    batch_results = list(helpers.resolve_batch(["8.8.8.8", "dns.google"]))
    assert len(batch_results) == 2
    batch_results = dict(batch_results)
    assert any([x in batch_results["dns.google"] for x in ("8.8.8.8", "8.8.4.4")])
    assert "dns.google" in batch_results["8.8.8.8"]
    # "any" type
    resolved = helpers.resolve("google.com", type="any")
    assert any([helpers.is_subdomain(h) for h in resolved])
    # wildcards
    assert helpers.is_wildcard("asdf.wat.blacklanternsecurity.github.io") == (True, "_wildcard.github.io")
    assert hash("github.io") in helpers.dns._wildcard_cache
    assert helpers.dns._wildcard_cache[hash("github.io")] == True
    assert helpers.is_wildcard("asdf.asdf.asdf.github.io") == (True, "_wildcard.github.io")
    assert helpers.is_wildcard("github.io") == (False, "github.io")
    assert helpers.is_wildcard("mail.google.com") == (False, "mail.google.com")
    wildcard_event1 = scan.make_event("wat.asdf.fdsa.github.io", "DNS_NAME", dummy=True)
    wildcard_event2 = scan.make_event("wats.asd.fdsa.github.io", "DNS_NAME", dummy=True)
    children, event_tags1, event_whitelisted1, event_blacklisted1 = scan.helpers.resolve_event(wildcard_event1)
    children, event_tags2, event_whitelisted2, event_blacklisted2 = scan.helpers.resolve_event(wildcard_event2)
    assert "wildcard" in event_tags1
    assert "wildcard" in event_tags2
    assert wildcard_event1.data == "_wildcard.github.io"
    assert wildcard_event2.data == "_wildcard.github.io"
    assert event_tags1 == event_tags2
    assert event_whitelisted1 == event_whitelisted2
    assert event_blacklisted1 == event_blacklisted2

    msg = "Ignore this error, it belongs here"

    def raise_e():
        raise Exception(msg)

    def raise_k():
        raise KeyboardInterrupt(msg)

    def raise_s():
        raise ScanCancelledError(msg)

    def raise_b():
        raise BrokenPipeError(msg)

    helpers.dns._catch_keyboardinterrupt(raise_e)
    helpers.dns._catch_keyboardinterrupt(raise_k)
    scan.manager.catch(raise_e, _on_finish_callback=raise_e)
    scan.manager.catch(raise_k)
    scan.manager.catch(raise_s)
    scan.manager.catch(raise_b)

    ## NTLM
    testheader = "TlRMTVNTUAACAAAAHgAeADgAAAAVgorilwL+bvnVipUAAAAAAAAAAJgAmABWAAAACgBjRQAAAA9XAEkATgAtAFMANAAyAE4ATwBCAEQAVgBUAEsAOAACAB4AVwBJAE4ALQBTADQAMgBOAE8AQgBEAFYAVABLADgAAQAeAFcASQBOAC0AUwA0ADIATgBPAEIARABWAFQASwA4AAQAHgBXAEkATgAtAFMANAAyAE4ATwBCAEQAVgBUAEsAOAADAB4AVwBJAE4ALQBTADQAMgBOAE8AQgBEAFYAVABLADgABwAIAHUwOZlfoNgBAAAAAA=="
    decoded = helpers.ntlm.ntlmdecode(testheader)
    assert decoded["NetBIOS_Domain_Name"] == "WIN-S42NOBDVTK8"
    assert decoded["NetBIOS_Computer_Name"] == "WIN-S42NOBDVTK8"
    assert decoded["DNS_Domain_name"] == "WIN-S42NOBDVTK8"
    assert decoded["FQDN"] == "WIN-S42NOBDVTK8"
    assert decoded["Timestamp"] == b"u09\x99_\xa0\xd8\x01"
    with pytest.raises(NTLMError):
        helpers.ntlm.ntlmdecode("asdf")

    # interact.sh
    interactsh_client = helpers.interactsh()
    with pytest.raises(InteractshError):
        interactsh_client.register()
    assert not list(interactsh_client.poll())
    with pytest.raises(InteractshError):
        interactsh_client.deregister()


def test_dns_resolvers(patch_requests, helpers):
    assert type(helpers.dns.resolvers) == set
    assert hasattr(helpers.dns.resolver_file, "is_file")
    assert hasattr(helpers.dns.mass_resolver_file, "is_file")


def test_word_cloud(helpers, bbot_config):
    number_mutations = helpers.word_cloud.get_number_mutations("base2_p013", n=5, padding=2)
    assert "base0_p013" in number_mutations
    assert "base7_p013" in number_mutations
    assert "base8_p013" not in number_mutations
    assert "base2_p008" in number_mutations
    assert "base2_p007" not in number_mutations
    assert "base2_p018" in number_mutations
    assert "base2_p0134" in number_mutations
    assert "base2_p0135" not in number_mutations

    permutations = helpers.word_cloud.mutations("_base", numbers=1)
    assert ("_base", "dev") in permutations
    assert ("dev", "_base") in permutations

    # saving and loading
    from bbot.scanner.scanner import Scanner

    scan1 = Scanner("127.0.0.1", config=bbot_config)
    word_cloud = scan1.helpers.word_cloud
    word_cloud.add_word("lantern")
    word_cloud.add_word("black")
    word_cloud.add_word("black")
    word_cloud.save()
    with open(word_cloud.default_filename) as f:
        word_cloud_content = [l.rstrip() for l in f.read().splitlines()]
    assert len(word_cloud_content) == 2
    assert "2\tblack" in word_cloud_content
    assert "1\tlantern" in word_cloud_content
    word_cloud.save(limit=1)
    with open(word_cloud.default_filename) as f:
        word_cloud_content = [l.rstrip() for l in f.read().splitlines()]
    assert len(word_cloud_content) == 1
    assert "2\tblack" in word_cloud_content
    assert "1\tlantern" not in word_cloud_content
    word_cloud.clear()
    with open(word_cloud.default_filename, "w") as f:
        f.write("plumbus\nrumbus")
    word_cloud.load()
    assert word_cloud["plumbus"] == 1
    assert word_cloud["rumbus"] == 1


def test_modules(patch_requests, patch_commands, scan, helpers, events, bbot_config):

    # base module _filter_event()
    from bbot.modules.base import BaseModule

    base_module = BaseModule(scan)
    localhost2 = scan.make_event("127.0.0.2", source=events.subdomain)
    localhost2.make_in_scope()
    # base cases
    assert base_module._filter_event("FINISHED") == True
    assert base_module._filter_event("WAT") == False
    base_module._watched_events = None
    base_module.watched_events = ["*"]
    assert base_module._filter_event("WAT") == False
    assert base_module._filter_event(events.emoji) == True
    base_module._watched_events = None
    base_module.watched_events = ["IP_ADDRESS"]
    assert base_module._filter_event(events.ipv4) == True
    assert base_module._filter_event(events.domain) == False
    assert base_module._filter_event(events.localhost) == True
    assert base_module._filter_event(localhost2) == True
    # target only
    base_module.target_only = True
    assert base_module._filter_event(localhost2) == False
    localhost2.tags.add("target")
    assert base_module._filter_event(localhost2) == True
    base_module.target_only = False
    # in scope only
    localhost3 = scan.make_event("127.0.0.2", source=events.subdomain)
    base_module.in_scope_only = True
    assert base_module._filter_event(events.localhost) == True
    assert base_module._filter_event(localhost3) == False
    base_module.in_scope_only = False
    # scope distance
    base_module.scope_distance_modifier = 0
    localhost2._scope_distance = 0
    assert base_module._filter_event(localhost2) == True
    localhost2._scope_distance = 1
    assert base_module._filter_event(localhost2) == True
    localhost2._scope_distance = 2
    assert base_module._filter_event(localhost2) == False
    localhost2._scope_distance = -1
    assert base_module._filter_event(localhost2) == False
    base_module.scope_distance_modifier = -1
    # special case for IPs and ranges
    base_module.watched_events = ["IP_ADDRESS", "IP_RANGE"]
    ip_range = scan.make_event("127.0.0.0/24", dummy=True)
    localhost4 = scan.make_event("127.0.0.1", source=ip_range)
    localhost4.make_in_scope()
    localhost4.module = "plumbus"
    assert base_module._filter_event(localhost4) == True
    localhost4.module = "speculate"
    assert base_module._filter_event(localhost4) == False

    from bbot.scanner.scanner import Scanner

    scan2 = Scanner(modules=list(available_modules), output_modules=list(available_output_modules), config=bbot_config)
    scan2.load_modules()
    scan2.status = "RUNNING"

    # attributes, descriptions, etc.
    for module_name, module in scan2.modules.items():
        # flags
        assert module._type in ("internal", "output", "scan")

    # module preloading
    all_preloaded = module_loader.preloaded()
    assert "massdns" in all_preloaded
    assert "DNS_NAME" in all_preloaded["massdns"]["watched_events"]
    assert "DNS_NAME" in all_preloaded["massdns"]["produced_events"]
    assert "subdomain-enum" in all_preloaded["massdns"]["flags"]
    assert "wordlist" in all_preloaded["massdns"]["config"]
    assert type(all_preloaded["massdns"]["config"]["max_resolvers"]) == int
    assert all_preloaded["sslcert"]["deps"]["pip"]
    assert all_preloaded["sslcert"]["deps"]["apt"]
    assert all_preloaded["massdns"]["deps"]["ansible"]

    for module_name, preloaded in all_preloaded.items():
        # either active or passive and never both
        flags = preloaded.get("flags", [])
        if preloaded["type"] == "scan":
            assert ("active" in flags and not "passive" in flags) or (
                not "active" in flags and "passive" in flags
            ), f'module "{module_name}" must have either "active" or "passive" flag'
            assert preloaded["meta"]["description"], f"{module_name} must have a description"

        # attribute checks
        watched_events = preloaded.get("watched_events")
        produced_events = preloaded.get("produced_events")

        assert type(watched_events) == list
        assert type(produced_events) == list
        assert watched_events, f"{module_name}.watched_events must not be empty"
        assert type(watched_events) == list, f"{module_name}.watched_events must be of type list"
        assert type(produced_events) == list, f"{module_name}.produced_events must be of type list"
        assert all(
            [type(t) == str for t in watched_events]
        ), f"{module_name}.watched_events entries must be of type string"
        assert all(
            [type(t) == str for t in produced_events]
        ), f"{module_name}.produced_events entries must be of type string"

        assert type(preloaded.get("deps_pip", [])) == list, f"{module_name}.deps_pipe must be of type list"
        assert type(preloaded.get("deps_apt", [])) == list, f"{module_name}.deps_apt must be of type list"
        assert type(preloaded.get("deps_shell", [])) == list, f"{module_name}.deps_shell must be of type list"
        assert type(preloaded.get("options", {})) == dict, f"{module_name}.options must be of type list"
        assert type(preloaded.get("options_desc", {})) == dict, f"{module_name}.options_desc must be of type list"
        # options must have descriptions
        assert set(preloaded.get("options", {})) == set(
            preloaded.get("options_desc", {})
        ), f"{module_name}.options do not match options_desc"
        # descriptions most not be blank
        assert all(
            o for o in preloaded.get("options_desc", {}).values()
        ), f"{module_name}.options_desc descriptions must not be blank"

    # setups
    futures = {}
    for module_name, module in scan2.modules.items():
        log.info(f"Testing {module_name}.setup()")
        future = scan2._thread_pool.submit_task(module.setup)
        futures[future] = module
    for future in helpers.as_completed(futures):
        module = futures[future]
        result = future.result()
        if type(result) == tuple:
            assert len(result) == 2, f"if tuple, {module.name}.setup() return value must have length of 2"
            status, msg = result
            assert status in (
                True,
                False,
                None,
            ), f"if tuple, the first element of {module.name}.setup()'s return value must be either True, False, or None"
            assert (
                type(msg) == str
            ), f"if tuple, the second element of {module.name}.setup()'s return value must be a message of type str"
        else:
            assert result in (
                True,
                False,
                None,
            ), f"{module.name}.setup() must return a status of either True, False, or None"
        if result == False:
            module.set_error_state()

    futures.clear()

    # handle_event / handle_batch
    futures = {}
    for module_name, module in scan2.modules.items():
        module.emit_event = lambda *args, **kwargs: None
        module._filter = lambda *args, **kwargs: True
        events_to_submit = [e for e in events.all if e.type in module.watched_events]
        if module.batch_size > 1:
            log.info(f"Testing {module_name}.handle_batch()")
            future = scan2._thread_pool.submit_task(module.handle_batch, *events_to_submit)
            futures[future] = module
        else:
            for e in events_to_submit:
                log.info(f"Testing {module_name}.handle_event()")
                future = scan2._thread_pool.submit_task(module.handle_event, e)
                futures[future] = module
    for future in helpers.as_completed(futures):
        try:
            assert future.result() == None
        except Exception as e:
            import traceback

            module = futures[future]
            assert module.errored == True, f'Error in module "{module}": {e}\n{traceback.format_exc()}'
    futures.clear()

    # finishes
    futures = {}
    for module_name, module in scan2.modules.items():
        log.info(f"Testing {module_name}.finish()")
        future = scan2._thread_pool.submit_task(module.finish)
        futures[future] = module
    for future in helpers.as_completed(futures):
        assert future.result() == None
    futures.clear()

    # cleanups
    futures = {}
    for module_name, module in scan2.modules.items():
        log.info(f"Testing {module_name}.cleanup()")
        future = scan2._thread_pool.submit_task(module.cleanup)
        futures[future] = module
    for future in helpers.as_completed(futures):
        assert future.result() == None
    futures.clear()

    # event filters
    for module_name, module in scan2.modules.items():
        log.info(f"Testing {module_name}.filter_event()")
        assert module.filter_event(events.emoji) in (True, False)


def test_config(bbot_config):
    from bbot.scanner.scanner import Scanner

    scan1 = Scanner("127.0.0.1", modules=["ipneighbor"], config=bbot_config)
    scan1.load_modules()
    assert scan1.config.plumbus == "asdf"
    assert scan1.modules["ipneighbor"].config.test_option == "ipneighbor"
    assert scan1.modules["human"].config.test_option == "human"
    assert scan1.modules["speculate"].config.test_option == "speculate"


def test_target(neuter_ansible, patch_requests, patch_commands, bbot_config):
    from bbot.scanner.scanner import Scanner

    scan1 = Scanner("api.publicapis.org", "8.8.8.8/30", "2001:4860:4860::8888/126", config=bbot_config)
    scan2 = Scanner("8.8.8.8/29", "publicapis.org", "2001:4860:4860::8888/125", config=bbot_config)
    scan3 = Scanner("8.8.8.8/29", "publicapis.org", "2001:4860:4860::8888/125", config=bbot_config)
    scan4 = Scanner("8.8.8.8/29", config=bbot_config)
    scan5 = Scanner(config=bbot_config)
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


def test_scan(neuter_ansible, patch_requests, patch_commands, events, bbot_config, helpers, neograph):
    from bbot.scanner.scanner import Scanner

    scan0 = Scanner("8.8.8.8/31", "evilcorp.com", blacklist=["8.8.8.8/28", "www.evilcorp.com"], config=bbot_config)
    assert scan0.whitelisted("8.8.8.8")
    assert scan0.whitelisted("8.8.8.9")
    assert scan0.blacklisted("8.8.8.15")
    assert not scan0.blacklisted("8.8.8.16")
    assert scan0.blacklisted("8.8.8.8/30")
    assert not scan0.blacklisted("8.8.8.8/27")
    assert not scan0.in_scope("8.8.8.8")
    assert scan0.whitelisted("api.evilcorp.com")
    assert scan0.whitelisted("www.evilcorp.com")
    assert not scan0.blacklisted("api.evilcorp.com")
    assert scan0.blacklisted("asdf.www.evilcorp.com")
    assert scan0.in_scope("test.api.evilcorp.com")
    assert not scan0.in_scope("test.www.evilcorp.com")
    assert not scan0.in_scope("www.evilcorp.co.uk")

    scan1 = Scanner("8.8.8.8", whitelist=["8.8.4.4"], config=bbot_config)
    assert not scan1.blacklisted("8.8.8.8")
    assert not scan1.blacklisted("8.8.4.4")
    assert not scan1.whitelisted("8.8.8.8")
    assert scan1.whitelisted("8.8.4.4")
    assert scan1.in_scope("8.8.4.4")
    assert not scan1.in_scope("8.8.8.8")

    scan2 = Scanner("8.8.8.8", config=bbot_config)
    assert not scan2.blacklisted("8.8.8.8")
    assert not scan2.blacklisted("8.8.4.4")
    assert scan2.whitelisted("8.8.8.8")
    assert not scan2.whitelisted("8.8.4.4")
    assert scan2.in_scope("8.8.8.8")
    assert not scan2.in_scope("8.8.4.4")

    scan3 = Scanner(
        "127.0.0.0/30",
        "127.0.0.2:8443",
        "https://localhost",
        "[::1]:80",
        "http://[::1]:8080",
        modules=["ipneighbor"],
        output_modules=list(available_output_modules),
        config=bbot_config,
        blacklist=["http://127.0.0.3:8000/asdf"],
        whitelist=["127.0.0.0/29"],
    )
    assert "targets" in scan3.json
    assert "127.0.0.3" in scan3.target
    assert "127.0.0.4" not in scan3.target
    assert "127.0.0.4" in scan3.whitelist
    assert scan3.whitelisted("127.0.0.4")
    assert "127.0.0.3" in scan3.blacklist
    assert scan3.blacklisted("127.0.0.3")
    assert scan3.in_scope("127.0.0.1")
    assert not scan3.in_scope("127.0.0.3")
    scan3.start()


def test_threadpool():
    from concurrent.futures import ThreadPoolExecutor
    from bbot.core.helpers.threadpool import ThreadPoolWrapper, NamedLock, as_completed

    with ThreadPoolExecutor(max_workers=3) as executor:
        pool = ThreadPoolWrapper(executor)
        add_one = lambda x: x + 1
        futures = [pool.submit_task(add_one, y) for y in [0, 1, 2, 3, 4]]
        results = []
        for f in as_completed(futures):
            results.append(f.result())
        assert tuple(sorted(results)) == (1, 2, 3, 4, 5)

    nl = NamedLock(max_size=5)
    for i in range(50):
        nl.get_lock(str(i))
    assert len(nl._cache) == 5
    assert tuple(nl._cache.keys()) == tuple(hash(str(x)) for x in [45, 46, 47, 48, 49])


def test_agent(agent):
    agent.start()
    agent.on_error(agent.ws, "test")
    agent.on_close(agent.ws, "test", "test")
    agent.on_open(agent.ws)
    agent.on_message(
        agent.ws,
        '{"conversation": "90196cc1-299f-4555-82a0-bc22a4247590", "command": "start_scan", "arguments": {"scan_id": "90196cc1-299f-4555-82a0-bc22a4247590", "targets": ["www.blacklanternsecurity.com"], "modules": ["ipneighbor"], "output_modules": ["human"]}}',
    )
    sleep(0.5)
    agent.scan_status()
    agent.stop_scan()


def test_cli(monkeypatch, bbot_config):

    from bbot import cli

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(cli, "config", bbot_config)
    monkeypatch.setattr(sys, "argv", ["bbot", "-y", "--current-config", "-t", "127.0.0.1", "-m", "ipneighbor"])
    cli.main()

    home_dir = Path(bbot_config["home"])
    monkeypatch.setattr(
        sys,
        "argv",
        ["bbot", "-y", "-t", "localhost", "-m", "ipneighbor", "-om", "human", "csv", "json", "-n", "test_scan"],
    )
    cli.main()
    scan_home = home_dir / "scans" / "test_scan"
    assert (scan_home / "wordcloud.tsv").is_file()
    assert (scan_home / "output.txt").is_file()
    assert (scan_home / "output.csv").is_file()
    assert (scan_home / "output.json").is_file()
    with open(scan_home / "output.csv") as f:
        lines = f.readlines()
        assert lines[0] == "Event type,Event data,Source Module,Scope Distance,Event Tags\n"
        assert len(lines) > 1


def test_depsinstaller(monkeypatch, neuter_ansible, bbot_config):
    # un-neuter ansible
    from bbot.core.helpers.depsinstaller import installer

    run, ensure_root = neuter_ansible
    ensure_root = installer.DepsInstaller.ensure_root
    monkeypatch.setattr(installer, "run", run)
    monkeypatch.setattr(installer.DepsInstaller, "ensure_root", ensure_root)

    from bbot.scanner.scanner import Scanner

    scan = Scanner(
        "127.0.0.1",
        modules=["dnsresolve"],
        config=bbot_config,
    )

    # test shell
    test_file = Path("/tmp/test_file")
    test_file.unlink(missing_ok=True)
    scan.helpers.depsinstaller.shell(module="plumbus", commands=[f"touch {test_file}"])
    assert test_file.is_file()
    test_file.unlink(missing_ok=True)

    # test tasks
    scan.helpers.depsinstaller.tasks(
        module="plumbus",
        tasks=[{"name": "test task execution", "ansible.builtin.shell": {"cmd": f"touch {test_file}"}}],
    )
    assert test_file.is_file()
    test_file.unlink(missing_ok=True)
