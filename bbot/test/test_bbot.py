import os
import sys
import pytest
import shutil
import logging
import ipaddress
from time import sleep

import bbot.core.logger  # noqa: F401
from bbot.core.configurator import available_modules, available_output_modules
from .scan import *
from .patches import *

log = logging.getLogger(f"bbot.test")


def test_events():

    assert ipv4_event.type == "IP_ADDRESS"
    assert ipv6_event.type == "IP_ADDRESS"
    assert netv4_event.type == "IP_RANGE"
    assert netv6_event.type == "IP_RANGE"
    assert domain_event.type == "DNS_NAME"
    assert "domain" in domain_event.tags
    assert subdomain_event.type == "DNS_NAME"
    assert "subdomain" in subdomain_event.tags
    assert open_port_event.type == "OPEN_TCP_PORT"
    assert url_event.type == "URL"
    assert ipv4_url_event.type == "URL"
    assert ipv6_url_event.type == "URL"

    # ip tests
    assert ipv4_event == scan.make_event("8.8.8.8", dummy=True)
    assert "8.8.8.8" in ipv4_event
    assert "8.8.8.8" == ipv4_event
    assert "8.8.8.8" in netv4_event
    assert "8.8.8.9" not in ipv4_event
    assert "8.8.9.8" not in netv4_event
    assert "2001:4860:4860::8888" in ipv6_event
    assert "2001:4860:4860::8888" in netv6_event
    assert "2001:4860:4860::8889" not in ipv6_event
    assert "2002:4860:4860::8888" not in netv6_event
    assert emoji_event not in ipv4_event
    assert emoji_event not in netv6_event
    assert netv6_event not in emoji_event

    # hostname tests
    assert domain_event.host == "publicapis.org"
    assert subdomain_event.host == "api.publicapis.org"
    assert domain_event.host_stem == "publicapis"
    assert subdomain_event.host_stem == "api.publicapis"
    assert "api.publicapis.org" in domain_event
    assert "api.publicapis.org" in subdomain_event
    assert "fsocie.ty" not in domain_event
    assert "fsocie.ty" not in subdomain_event
    assert subdomain_event in domain_event
    assert domain_event not in subdomain_event
    assert not ipv4_event in domain_event
    assert not netv6_event in domain_event
    assert emoji_event not in domain_event
    assert domain_event not in emoji_event

    # url tests
    assert url_event.host == "api.publicapis.org"
    assert url_event in domain_event
    assert url_event in subdomain_event
    assert "api.publicapis.org:443" in url_event
    assert "publicapis.org" not in url_event
    assert ipv4_url_event in ipv4_event
    assert ipv4_url_event in netv4_event
    assert ipv6_url_event in ipv6_event
    assert ipv6_url_event in netv6_event
    assert emoji_event not in url_event
    assert emoji_event not in ipv6_url_event
    assert url_event not in emoji_event

    # open port tests
    assert open_port_event in domain_event
    assert "api.publicapis.org:443" in open_port_event
    assert "bad.publicapis.org:443" not in open_port_event
    assert "publicapis.org:443" not in open_port_event
    assert ipv4_open_port_event in ipv4_event
    assert ipv4_open_port_event in netv4_event
    assert "8.8.8.9" not in ipv4_open_port_event
    assert ipv6_open_port_event in ipv6_event
    assert ipv6_open_port_event in netv6_event
    assert "2002:4860:4860::8888" not in ipv6_open_port_event
    assert emoji_event not in ipv6_open_port_event
    assert ipv6_open_port_event not in emoji_event

    # attribute tests
    assert ipv4_event.host == ipaddress.ip_address("8.8.8.8")
    assert ipv4_event.port is None
    assert ipv6_event.host == ipaddress.ip_address("2001:4860:4860::8888")
    assert ipv6_event.port is None
    assert domain_event.port is None
    assert subdomain_event.port is None
    assert open_port_event.host == "api.publicapis.org"
    assert open_port_event.port == 443
    assert ipv4_open_port_event.host == ipaddress.ip_address("8.8.8.8")
    assert ipv4_open_port_event.port == 443
    assert ipv6_open_port_event.host == ipaddress.ip_address("2001:4860:4860::8888")
    assert ipv6_open_port_event.port == 443
    assert url_event.host == "api.publicapis.org"
    assert url_event.port == 443
    assert ipv4_url_event.host == ipaddress.ip_address("8.8.8.8")
    assert ipv4_url_event.port == 443
    assert ipv6_url_event.host == ipaddress.ip_address("2001:4860:4860::8888")
    assert ipv6_url_event.port == 443


def test_helpers(monkeypatch):

    ### MISC ###
    assert helpers.is_domain("evilcorp.co.uk")
    assert not helpers.is_domain("www.evilcorp.co.uk")
    assert helpers.is_subdomain("www.evilcorp.co.uk")
    assert not helpers.is_subdomain("evilcorp.co.uk")
    assert helpers.is_ip("127.0.0.1")
    assert not helpers.is_ip("publicapis.org")

    ### COMMAND ###
    assert "plumbus\n" in helpers.run(["echo", "plumbus"], text=True).stdout
    assert "plumbus\n" in list(helpers.run_live(["echo", "plumbus"]))
    assert "plumbus\n" in list(helpers.run_live(["cat"], input="lumbus\nplumbus"))

    def plumbus_generator():
        yield "lumbus"
        yield "plumbus"

    assert "plumbus\n" in list(helpers.run_live(["cat"], input=plumbus_generator()))
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

    ### WEB ###
    assert getattr(helpers.request("https://api.publicapis.org/health"), "text", "").startswith("{")
    assert getattr(helpers.request("https://api.publicapis.org/health", cache_for=60), "text", "").startswith("{")
    helpers.download("https://api.publicapis.org/health", cache_hrs=1)
    assert helpers.is_cached("https://api.publicapis.org/health")

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
    # wildcards
    assert helpers.is_wildcard("blacklanternsecurity.github.io")
    assert "github.io" in scan.helpers.dns.wildcards
    assert not helpers.is_wildcard("mail.google.com")
    # resolvers - disabled because github's dns is wack
    patch_requests(monkeypatch)
    assert type(helpers.dns.resolvers) == set
    assert hasattr(helpers.dns.resolver_file, "is_file")


def test_word_cloud():

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


def test_target():
    scan1 = Scanner("publicapis.org", "8.8.8.8/30", "2001:4860:4860::8888/126")
    scan2 = Scanner("8.8.8.8/30", "publicapis.org", "2001:4860:4860::8888/126")
    scan3 = Scanner("8.8.8.8/31")
    assert "8.8.8.9" in scan1.target
    assert not "8.8.8.12" in scan1.target
    assert "2001:4860:4860::8889" in scan1.target
    assert not "2001:4860:4860::888c" in scan1.target
    assert "api.publicapis.org" in scan1.target
    assert scan1.target in scan2.target
    assert scan1.target == scan2.target
    assert scan2.target in scan1.target
    assert scan3.target in scan1.target
    assert not scan1.target in scan3.target
    assert scan3.target != scan1.target


def test_scan(monkeypatch):

    scan2 = Scanner(
        "publicapis.org",
        "8.8.8.8",
        "2001:4860:4860::8888",
        modules=["dnsresolve"],
        output_modules=list(available_output_modules),
        config=config,
    )
    scan2.json
    scan2.start()

    scan3 = Scanner(
        "publicapis.org",
        "8.8.8.8/32",
        "2001:4860:4860::8888/128",
        modules=list(available_modules),
        config=config,
    )

    # nuke web requests
    patch_requests(monkeypatch)
    patch_commands(monkeypatch)

    monkeypatch.setattr(scan3.helpers, "request", lambda *args, **kwargs: requests_response)
    Path("/tmp/nope").touch()
    monkeypatch.setattr(scan3.helpers, "download", lambda *args, **kwargs: "/tmp/nope")

    scan3.setup_modules(remove_failed=False)

    futures = []
    for module in scan3.modules.values():
        module.emit_event = lambda *args, **kwargs: None
        module._filter_event = lambda *args, **kwargs: True
        events_to_submit = [e for e in all_events if e.type in module.watched_events]
        if module.batch_size > 1:
            log.debug(f"Testing {module.name}.handle_batch()")
            # future = scan3.helpers.submit_task(module.handle_batch, *events_to_submit)
            # futures.append(future)
            module.handle_batch(*events_to_submit)
        else:
            for e in events_to_submit:
                log.debug(f"Testing {module.name}.handle_event()")
                # future = scan3.helpers.submit_task(module.handle_event, e)
                # futures.append(future)
                module.handle_event(e)
    for future in helpers.as_completed(futures):
        assert future.result() is None

    scan3._thread_pool.shutdown(wait=True)


def test_agent(monkeypatch):
    class WebSocketApp:
        def __init__(*args, **kwargs):
            return

        def send(self, message):
            assert type(message) == str

        def run_forever(*args, **kwargs):
            return False

    from bbot import agent
    from bbot.modules.output.websocket import Websocket

    monkeypatch.setattr(Websocket, "send", lambda *args, **kwargs: True)

    test_agent = agent.Agent({"agent_url": "test", "agent_token": "test"})
    test_agent.setup()
    monkeypatch.setattr(test_agent, "ws", WebSocketApp())
    test_agent.start()
    test_agent.on_error(test_agent.ws, "test")
    test_agent.on_close(test_agent.ws, "test", "test")
    test_agent.on_open(test_agent.ws)
    test_agent.on_message(
        test_agent.ws,
        '{"conversation": "90196cc1-299f-4555-82a0-bc22a4247590", "command": "start_scan", "arguments": {"scan_id": "90196cc1-299f-4555-82a0-bc22a4247590", "targets": ["www.blacklanternsecurity.com"], "modules": ["dnsresolve"], "output_modules": ["human"]}}',
    )
    sleep(0.5)
    test_agent.scan_status()
    test_agent.stop_scan()


class NeoGraph:
    def __init__(self, *args, **kwargs):
        pass

    def merge(self, *args, **kwargs):
        return True


@pytest.fixture
def neograph():
    return NeoGraph


def test_db(monkeypatch, neograph):
    from bbot.db.neo4j import Neo4j
    import py2neo

    monkeypatch.setattr(py2neo, "Graph", neograph)
    n = Neo4j(uri="bolt://127.0.0.1:1111")
    n.insert_event(ipv4_event)
    n.insert_events([ipv4_event])

    scan4 = Scanner(
        "doesnot.exist",
        modules=["dnsresolve"],
        output_modules=["neo4j"],
        config=config,
    )
    scan4.start()


def test_cli(monkeypatch):

    from bbot import cli

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(sys, "argv", ["bbot", "-t", "doesnot.exist", "-m", "dnsresolve"])
    cli.main()
    monkeypatch.setattr(sys, "argv", ["bbot", "--current-config"])
    cli.main()
    monkeypatch.setattr(sys, "argv", ["bbot", "-t", "doesnot.exist", "-m", "plumbus"])
    cli.main()


# wipe out bbot home dir
import atexit

atexit.register(shutil.rmtree, "/tmp/.bbot_test", ignore_errors=True)
