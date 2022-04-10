import os
import logging
import ipaddress

import bbot.core.logger  # noqa: F401
from .scan import *

log = logging.getLogger(f"bbot.test")


def test_events():

    assert ipv4_event.type == "IPV4_ADDRESS"
    assert ipv6_event.type == "IPV6_ADDRESS"
    assert netv4_event.type == "IPV4_RANGE"
    assert netv6_event.type == "IPV6_RANGE"
    assert domain_event.type == "DNS_NAME"
    assert "domain" in domain_event.tags
    assert subdomain_event.type == "DNS_NAME"
    assert "subdomain" in subdomain_event.tags
    assert open_port_event.type == "OPEN_TCP_PORT"
    assert url_event.type == "URL"
    assert ipv4_url_event.type == "URL"
    assert ipv6_url_event.type == "URL"

    # ip tests
    assert ipv4_event == scan.make_event("192.168.1.1", dummy=True)
    assert "192.168.1.1" in ipv4_event
    assert "192.168.1.1" in netv4_event
    assert "192.168.1.2" not in ipv4_event
    assert "192.168.2.1" not in netv4_event
    assert "dead::beef" in ipv6_event
    assert "dead::beef" in netv6_event
    assert "dead::babe" not in ipv6_event
    assert "cafe::babe" not in netv6_event
    assert emoji_event not in ipv4_event
    assert emoji_event not in netv6_event
    assert netv6_event not in emoji_event

    # hostname tests
    assert domain_event.host == "evilcorp.com"
    assert subdomain_event.host == "www.evilcorp.com"
    assert domain_event.host_stem == "evilcorp"
    assert subdomain_event.host_stem == "www.evilcorp"
    assert "www.evilcorp.com" in domain_event
    assert "www.evilcorp.com" in subdomain_event
    assert "fsocie.ty" not in domain_event
    assert "fsocie.ty" not in subdomain_event
    assert subdomain_event in domain_event
    assert domain_event not in subdomain_event
    assert not ipv4_event in domain_event
    assert not netv6_event in domain_event
    assert emoji_event not in domain_event
    assert domain_event not in emoji_event

    # url tests
    assert url_event.host == "url.www.evilcorp.com"
    assert url_event in domain_event
    assert url_event in subdomain_event
    assert "url.www.evilcorp.com:666" in url_event
    assert "www.evilcorp.com" not in url_event
    assert ipv4_url_event in ipv4_event
    assert ipv4_url_event in netv4_event
    assert ipv6_url_event in ipv6_event
    assert ipv6_url_event in netv6_event
    assert emoji_event not in url_event
    assert emoji_event not in ipv6_url_event
    assert url_event not in emoji_event

    # open port tests
    assert open_port_event in domain_event
    assert "port.www.evilcorp.com:777" in open_port_event
    assert "bad.www.evilcorp.com:777" not in open_port_event
    assert "www.evilcorp.com:777" not in open_port_event
    assert ipv4_open_port_event in ipv4_event
    assert ipv4_open_port_event in netv4_event
    assert "192.168.1.2" not in ipv4_open_port_event
    assert ipv6_open_port_event in ipv6_event
    assert ipv6_open_port_event in netv6_event
    assert "cafe::babe" not in ipv6_open_port_event
    assert emoji_event not in ipv6_open_port_event
    assert ipv6_open_port_event not in emoji_event

    # attribute tests
    assert ipv4_event.host == ipaddress.ip_address("192.168.1.1")
    assert ipv4_event.port is None
    assert ipv6_event.host == ipaddress.ip_address("dead::beef")
    assert ipv6_event.port is None
    assert domain_event.port is None
    assert subdomain_event.port is None
    assert open_port_event.host == "port.www.evilcorp.com"
    assert open_port_event.port == 777
    assert ipv4_open_port_event.host == ipaddress.ip_address("192.168.1.1")
    assert ipv4_open_port_event.port == 80
    assert ipv6_open_port_event.host == ipaddress.ip_address("dead::beef")
    assert ipv6_open_port_event.port == 80
    assert url_event.host == "url.www.evilcorp.com"
    assert url_event.port == 666
    assert ipv4_url_event.host == ipaddress.ip_address("192.168.1.1")
    assert ipv4_url_event.port == 666
    assert ipv6_url_event.host == ipaddress.ip_address("dead::beef")
    assert ipv6_url_event.port == 666


def test_helpers():

    ### MISC ###
    assert helpers.is_domain("evilcorp.co.uk")
    assert not helpers.is_domain("www.evilcorp.co.uk")
    assert helpers.is_subdomain("www.evilcorp.co.uk")
    assert not helpers.is_subdomain("evilcorp.co.uk")
    assert helpers.is_ip("127.0.0.1")
    assert not helpers.is_ip("evilcorp.com")

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

    ### WEB ###
    assert getattr(helpers.request("https://api.publicapis.org/health"), "text", "").startswith("{")
    helpers.download("https://api.publicapis.org/health", cache_hrs=1)
    assert helpers.is_cached("https://api.publicapis.org/health")

    ### DNS ###
    # resolution
    assert all([helpers.is_ip(i) for i in helpers.resolve("scanme.nmap.org")])
    assert "dns.google" in helpers.resolve("8.8.8.8")
    assert any([helpers.is_subdomain(h) for h in helpers.resolve("google.com", type="mx")])
    v6_ips = helpers.resolve("www.google.com", type="AAAA")
    assert all([i.version == 6 for i in [ipaddress.ip_address(_) for _ in v6_ips]])
    assert not helpers.resolve(f"{helpers.rand_string(length=30)}.com")
    # wildcards
    assert helpers.is_wildcard("blacklanternsecurity.github.io")
    assert "github.io" in scan.helpers.dns.wildcards
    assert not helpers.is_wildcard("mail.google.com")
    # resolvers - disabled because github's dns is wack
    # assert "8.8.8.8" in helpers.resolver_list()


def test_modules():

    method_futures = {"setup": {}, "finish": {}, "cleanup": {}}
    filter_futures = {}
    for module_name, module in scan.modules.items():
        # attribute checks
        assert type(module.watched_events) == list
        assert type(module.produced_events) == list
        assert all([type(t) == str for t in module.watched_events])
        assert all([type(t) == str for t in module.produced_events])

        # test setups and cleanups etc.
        for method_name in ("setup", "finish", "cleanup"):
            method = getattr(module, method_name)
            future = helpers.submit_task(method)
            method_futures[method_name][future] = module

        # module event filters
        filter_future = helpers.submit_task(module.filter_event, emoji_event)
        filter_futures[filter_future] = module

    for method_name, futures in method_futures.items():
        if method_name in ("setup"):
            expected_return_values = (True, False)
        else:
            expected_return_values = (None,)
        for future in helpers.as_completed(futures):
            module = futures[future]
            log.info(f"Testing {module.name}.{method_name}()")
            assert future.result() in expected_return_values

    for filter_future in helpers.as_completed(filter_futures):
        module = filter_futures[filter_future]
        log.info(f"Testing {module.name}.filter_event()")
        assert filter_future.result() in (True, False)
