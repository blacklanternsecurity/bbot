import os
import sys
import shutil
import logging
import ipaddress
from time import sleep

import bbot.core.logger  # noqa: F401
from bbot.core.configurator import available_modules, available_output_modules
from .bbot_fixtures import *  # noqa: F401

log = logging.getLogger(f"bbot.test")

os.environ["BBOT_SUDO_PASS"] = "nah"


def test_events(events, scan):

    assert events.ipv4.type == "IP_ADDRESS"
    assert events.ipv6.type == "IP_ADDRESS"
    assert events.netv4.type == "IP_RANGE"
    assert events.netv6.type == "IP_RANGE"
    assert events.domain.type == "DNS_NAME"
    assert "domain" in events.domain.tags
    assert events.subdomain.type == "DNS_NAME"
    assert "subdomain" in events.subdomain.tags
    assert events.open_port.type == "OPEN_TCP_PORT"
    assert events.url.type == "URL"
    assert events.ipv4_url.type == "URL"
    assert events.ipv6_url.type == "URL"

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

    # url tests
    assert events.url.host == "api.publicapis.org"
    assert events.url in events.domain
    assert events.url in events.subdomain
    assert "api.publicapis.org:443" in events.url
    assert "publicapis.org" not in events.url
    assert events.ipv4_url in events.ipv4
    assert events.ipv4_url in events.netv4
    assert events.ipv6_url in events.ipv6
    assert events.ipv6_url in events.netv6
    assert events.emoji not in events.url
    assert events.emoji not in events.ipv6_url
    assert events.url not in events.emoji
    assert "https://evilcorp.com" == scan.make_event("https://evilcorp.com:443", dummy=True)
    assert "http://evilcorp.com" == scan.make_event("http://evilcorp.com:80", dummy=True)
    assert "https://evilcorp.com:443" == scan.make_event("https://evilcorp.com", dummy=True)
    assert "http://evilcorp.com:80" == scan.make_event("http://evilcorp.com", dummy=True)
    assert "https://evilcorp.com:80" == scan.make_event("https://evilcorp.com:80", dummy=True)
    assert "http://evilcorp.com:443" == scan.make_event("http://evilcorp.com:443", dummy=True)

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
    assert events.url.host == "api.publicapis.org"
    assert events.url.port == 443
    assert events.ipv4_url.host == ipaddress.ip_address("8.8.8.8")
    assert events.ipv4_url.port == 443
    assert events.ipv6_url.host == ipaddress.ip_address("2001:4860:4860::8888")
    assert events.ipv6_url.port == 443


def test_helpers(patch_requests, patch_commands, helpers):

    old_run, old_run_live = patch_commands

    ### MISC ###
    assert helpers.is_domain("evilcorp.co.uk")
    assert not helpers.is_domain("www.evilcorp.co.uk")
    assert helpers.is_subdomain("www.evilcorp.co.uk")
    assert not helpers.is_subdomain("evilcorp.co.uk")
    assert helpers.parent_domain("www.evilcorp.co.uk") == "evilcorp.co.uk"
    assert helpers.parent_domain("evilcorp.co.uk") == "evilcorp.co.uk"
    assert list(helpers.domain_parents("test.www.evilcorp.co.uk")) == ["www.evilcorp.co.uk", "evilcorp.co.uk"]
    assert list(helpers.domain_parents("www.evilcorp.co.uk", include_self=True)) == [
        "www.evilcorp.co.uk",
        "evilcorp.co.uk",
    ]
    assert list(helpers.ip_network_parents("0.0.0.0/2")) == [
        ipaddress.ip_network("0.0.0.0/1"),
        ipaddress.ip_network("0.0.0.0/0"),
    ]
    assert list(helpers.ip_network_parents("0.0.0.0/1", include_self=True)) == [
        ipaddress.ip_network("0.0.0.0/1"),
        ipaddress.ip_network("0.0.0.0/0"),
    ]
    assert helpers.is_ip("127.0.0.1")
    assert not helpers.is_ip("publicapis.org")
    extracted_words = helpers.extract_words("blacklanternsecurity")
    assert "black" in extracted_words
    assert "blacklantern" in extracted_words
    assert "lanternsecurity" in extracted_words
    assert "blacklanternsecurity" in extracted_words
    assert "bls" in extracted_words
    ipv4_netloc = helpers.make_netloc("192.168.1.1", 80)
    assert ipv4_netloc == "192.168.1.1:80"
    ipv6_netloc = helpers.make_netloc("dead::beef", "443")
    assert ipv6_netloc == "[dead::beef]:443"

    assert helpers.search_dict_by_key("asdf", {"asdf": "fdsa"}) == "fdsa"
    assert helpers.search_dict_by_key("asdf", {"wat": {"asdf": "fdsa"}}) == "fdsa"
    assert helpers.search_dict_by_key("asdf", [{"wat": {"nope": 1}}, {"wat": [{"asdf": "fdsa"}]}]) == "fdsa"
    with pytest.raises(KeyError, match=".*asdf.*"):
        helpers.search_dict_by_key("asdf", [{"wat": {"nope": 1}}, {"wat": [{"fdsa": "asdf"}]}])
    with pytest.raises(KeyError, match=".*asdf.*"):
        helpers.search_dict_by_key("asdf", "asdf")

    ### COMMAND ###
    assert "plumbus\n" in old_run(helpers, ["echo", "plumbus"], text=True).stdout
    assert "plumbus\n" in list(old_run_live(helpers, ["echo", "plumbus"]))
    assert "plumbus\n" in list(old_run_live(helpers, ["cat"], input="lumbus\nplumbus"))

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

    ### WEB ###
    request, download = patch_requests
    assert getattr(request(helpers, "https://api.publicapis.org/health"), "text", "").startswith("{")
    assert getattr(request(helpers, "https://api.publicapis.org/health", cache_for=60), "text", "").startswith("{")
    download(helpers, "https://api.publicapis.org/health", cache_hrs=1)
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
    # batch resolution
    batch_results = list(helpers.resolve_batch("8.8.8.8", "dns.google"))
    assert len(batch_results) == 2
    batch_results = dict(batch_results)
    assert any([x in batch_results["dns.google"] for x in ("8.8.8.8", "8.8.4.4")])
    assert "dns.google" in batch_results["8.8.8.8"]
    # "any" type
    resolved = helpers.resolve("google.com", type="any")
    assert any([helpers.is_subdomain(h) for h in resolved])
    # wildcards
    assert helpers.is_wildcard("blacklanternsecurity.github.io")
    assert "github.io" in helpers.dns.wildcards
    assert not helpers.is_wildcard("mail.google.com")
    # resolvers - disabled because github's dns is wack


def test_dns_resolvers(patch_requests, helpers):
    assert type(helpers.dns.resolvers) == set
    assert hasattr(helpers.dns.resolver_file, "is_file")


def test_word_cloud(helpers):
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


def test_modules(patch_requests, patch_commands, scan, helpers, events):

    method_futures = {"setup": {}, "finish": {}, "cleanup": {}}
    filter_futures = {}
    for module_name, module in scan.modules.items():
        # attribute checks
        assert type(module.watched_events) == list
        assert type(module.produced_events) == list
        assert all([type(t) == str for t in module.watched_events])
        assert all([type(t) == str for t in module.produced_events])

        assert type(module.deps_pip) == list
        assert type(module.deps_apt) == list
        assert type(module.deps_shell) == list
        assert type(module.options) == dict
        assert type(module.options_desc) == dict
        # options must have descriptions
        assert set(module.options) == set(module.options_desc)
        # descriptions most not be blank
        assert all(o for o in module.options_desc.values())

        # test setups and cleanups etc.
        for method_name in ("setup", "finish", "cleanup"):
            method = getattr(module, method_name)
            future = scan._thread_pool.submit_task(method)
            method_futures[method_name][future] = module

        # module event filters
        filter_future = scan._thread_pool.submit_task(module.filter_event, events.emoji)
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


def test_target(neuter_ansible, patch_requests, patch_commands):
    from bbot.scanner.scanner import Scanner

    scan1 = Scanner("api.publicapis.org", "8.8.8.8/30", "2001:4860:4860::8888/126")
    scan2 = Scanner("8.8.8.8/29", "publicapis.org", "2001:4860:4860::8888/125")
    scan3 = Scanner("8.8.8.8/29", "publicapis.org", "2001:4860:4860::8888/125")
    scan4 = Scanner("8.8.8.8/29")
    scan5 = Scanner()
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
    assert scan1.make_event("https://[2001:4860:4860::8888]:80", "URL", dummy=True) in scan1.target
    assert scan1.make_event("[2001:4860:4860::8888]:80", "OPEN_TCP_PORT", dummy=True) in scan1.target
    assert scan1.make_event("[2001:4860:4860::888c]:80", "OPEN_TCP_PORT", dummy=True) not in scan1.target
    assert scan1.target in scan2.target
    assert scan2.target not in scan1.target
    assert scan3.target in scan2.target
    assert scan2.target == scan3.target
    assert scan4.target != scan1.target


def test_scan(neuter_ansible, patch_requests, patch_commands, events, config, helpers):
    from bbot.scanner.scanner import Scanner

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

    scan3.setup_modules(remove_failed=False)

    for module in scan3.modules.values():
        module.emit_event = lambda *args, **kwargs: None
        module._filter = lambda *args, **kwargs: True
        events_to_submit = [e for e in events.all if e.type in module.watched_events]
        if module.batch_size > 1:
            log.debug(f"Testing {module.name}.handle_batch()")
            module.handle_batch(*events_to_submit)
        else:
            for e in events_to_submit:
                log.debug(f"Testing {module.name}.handle_event()")
                module.handle_event(e)

    scan3._thread_pool.shutdown(wait=True)


def test_agent(agent):
    agent.start()
    agent.on_error(agent.ws, "test")
    agent.on_close(agent.ws, "test", "test")
    agent.on_open(agent.ws)
    agent.on_message(
        agent.ws,
        '{"conversation": "90196cc1-299f-4555-82a0-bc22a4247590", "command": "start_scan", "arguments": {"scan_id": "90196cc1-299f-4555-82a0-bc22a4247590", "targets": ["www.blacklanternsecurity.com"], "modules": ["dnsresolve"], "output_modules": ["human"]}}',
    )
    sleep(0.5)
    agent.scan_status()
    agent.stop_scan()


def test_db(neuter_ansible, patch_requests, patch_commands, neograph, events, config):
    from bbot.scanner.scanner import Scanner

    scan4 = Scanner(
        "127.0.0.1",
        modules=["dnsresolve"],
        output_modules=["neo4j"],
        config=config,
    )
    scan4.start()


def test_cli(monkeypatch):

    from bbot import cli

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(sys, "argv", ["bbot", "-t", "127.0.0.1", "-m", "dnsresolve"])
    cli.main()
    monkeypatch.setattr(sys, "argv", ["bbot", "--current-config"])
    cli.main()
    monkeypatch.setattr(sys, "argv", ["bbot", "-t", "127.0.0.1", "-m", "plumbus"])
    cli.main()


def test_depsinstaller(monkeypatch, neuter_ansible, config):
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
        config=config,
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


# wipe out bbot home dir
import atexit

atexit.register(shutil.rmtree, "/tmp/.bbot_test", ignore_errors=True)
