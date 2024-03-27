import re

from ..bbot_fixtures import *

from bbot.modules.base import BaseModule
from bbot.modules.output.base import BaseOutputModule
from bbot.modules.report.base import BaseReportModule
from bbot.modules.internal.base import BaseInternalModule


@pytest.mark.asyncio
async def test_modules_basic(scan, helpers, events, bbot_config, bbot_scanner, httpx_mock):
    fallback_nameservers = scan.helpers.temp_dir / "nameservers.txt"
    with open(fallback_nameservers, "w") as f:
        f.write("8.8.8.8\n")

    for http_method in ("GET", "CONNECT", "HEAD", "POST", "PUT", "TRACE", "DEBUG", "PATCH", "DELETE", "OPTIONS"):
        httpx_mock.add_response(method=http_method, url=re.compile(r".*"), json={"test": "test"})

    # output module specific event filtering tests
    base_output_module_1 = BaseOutputModule(scan)
    base_output_module_1.watched_events = ["IP_ADDRESS"]
    localhost = scan.make_event("127.0.0.1", source=scan.root_event)
    assert base_output_module_1._event_precheck(localhost)[0] == True
    localhost._internal = True
    assert base_output_module_1._event_precheck(localhost)[0] == False
    localhost._internal = False
    assert base_output_module_1._event_precheck(localhost)[0] == True
    localhost._omit = True
    assert base_output_module_1._event_precheck(localhost)[0] == True

    base_output_module_2 = BaseOutputModule(scan)
    base_output_module_2.watched_events = ["*"]
    localhost = scan.make_event("127.0.0.1", source=scan.root_event)
    assert base_output_module_2._event_precheck(localhost)[0] == True
    localhost._internal = True
    assert base_output_module_2._event_precheck(localhost)[0] == False
    localhost._internal = False
    assert base_output_module_2._event_precheck(localhost)[0] == True
    localhost._omit = True
    assert base_output_module_2._event_precheck(localhost)[0] == False

    # common event filtering tests
    for module_class in (BaseModule, BaseOutputModule, BaseReportModule, BaseInternalModule):
        base_module = module_class(scan)
        localhost2 = scan.make_event("127.0.0.2", source=events.subdomain)
        localhost2.scope_distance = 0
        # base cases
        base_module._watched_events = None
        base_module.watched_events = ["*"]
        assert base_module._event_precheck(events.emoji)[0] == True
        base_module._watched_events = None
        base_module.watched_events = ["IP_ADDRESS"]
        assert base_module._event_precheck(events.ipv4)[0] == True
        assert base_module._event_precheck(events.domain)[0] == False
        assert base_module._event_precheck(events.localhost)[0] == True
        assert base_module._event_precheck(localhost2)[0] == True
        # target only
        base_module.target_only = True
        assert base_module._event_precheck(localhost2)[0] == False
        localhost2.add_tag("target")
        assert base_module._event_precheck(localhost2)[0] == True
        base_module.target_only = False

        # in scope only
        base_module.in_scope_only = True
        localhost3 = scan.make_event("127.0.0.2", source=events.subdomain)
        valid, reason = await base_module._event_postcheck(localhost3)
        if base_module._type == "output":
            assert valid
        else:
            assert not valid
            assert reason == "it did not meet in_scope_only filter criteria"
        base_module.in_scope_only = False
        base_module.scope_distance_modifier = 0
        valid, reason = await base_module._event_postcheck(events.localhost)
        assert valid

    base_output_module = BaseOutputModule(scan)
    base_output_module.watched_events = ["IP_ADDRESS"]

    scan2 = bbot_scanner(
        modules=list(set(available_modules + available_internal_modules)),
        output_modules=list(available_output_modules),
        config=bbot_config,
        force_start=True,
    )
    scan2.helpers.dns.fallback_nameservers_file = fallback_nameservers
    await scan2.load_modules()
    scan2.status = "RUNNING"

    # attributes, descriptions, etc.
    # TODO: Ensure every flag has a description
    for module_name, module in sorted(scan2.modules.items()):
        # flags
        assert module._type in ("internal", "output", "scan")
        # async stuff
        not_async = []
        for func_name in ("setup", "ping", "filter_event", "handle_event", "finish", "report", "cleanup"):
            f = getattr(module, func_name)
            if not scan2.helpers.is_async_function(f):
                log.error(f"{f.__qualname__}() is not async")
                not_async.append(f)
    assert not any(not_async)

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

    all_flags = set()

    for module_name, preloaded in all_preloaded.items():
        # either active or passive and never both
        flags = preloaded.get("flags", [])
        for flag in flags:
            all_flags.add(flag)
        if preloaded["type"] == "scan":
            assert ("active" in flags and not "passive" in flags) or (
                not "active" in flags and "passive" in flags
            ), f'module "{module_name}" must have either "active" or "passive" flag'
            assert ("safe" in flags and not "aggressive" in flags) or (
                not "safe" in flags and "aggressive" in flags
            ), f'module "{module_name}" must have either "safe" or "aggressive" flag'
            assert preloaded.get("meta", {}).get("description", ""), f"{module_name} must have a description"

        # attribute checks
        watched_events = preloaded.get("watched_events")
        produced_events = preloaded.get("produced_events")

        assert type(watched_events) == list
        assert type(produced_events) == list
        if not preloaded.get("type", "") in ("internal",):
            assert watched_events, f"{module_name}.watched_events must not be empty"
        assert type(watched_events) == list, f"{module_name}.watched_events must be of type list"
        assert type(produced_events) == list, f"{module_name}.produced_events must be of type list"
        assert all(
            [type(t) == str for t in watched_events]
        ), f"{module_name}.watched_events entries must be of type string"
        assert all(
            [type(t) == str for t in produced_events]
        ), f"{module_name}.produced_events entries must be of type string"

        assert type(preloaded.get("deps_pip", [])) == list, f"{module_name}.deps_pip must be of type list"
        assert (
            type(preloaded.get("deps_pip_constraints", [])) == list
        ), f"{module_name}.deps_pip_constraints must be of type list"
        assert type(preloaded.get("deps_apt", [])) == list, f"{module_name}.deps_apt must be of type list"
        assert type(preloaded.get("deps_shell", [])) == list, f"{module_name}.deps_shell must be of type list"
        assert type(preloaded.get("config", None)) == dict, f"{module_name}.options must be of type list"
        assert type(preloaded.get("options_desc", None)) == dict, f"{module_name}.options_desc must be of type list"
        # options must have descriptions
        assert set(preloaded.get("config", {})) == set(
            preloaded.get("options_desc", {})
        ), f"{module_name}.options do not match options_desc"
        # descriptions most not be blank
        assert all(
            o for o in preloaded.get("options_desc", {}).values()
        ), f"{module_name}.options_desc descriptions must not be blank"

    from bbot.core.flags import flag_descriptions

    for flag in all_flags:
        assert flag in flag_descriptions, f'Flag "{flag}" not listed in bbot/core/flags.py'
        description = flag_descriptions.get(flag, "")
        assert description, f'Flag "{flag}" has no description in bbot/core/flags.py'


@pytest.mark.asyncio
async def test_modules_basic_perhostonly(helpers, events, bbot_config, bbot_scanner, httpx_mock, monkeypatch):
    from bbot.modules.base import BaseModule

    class mod_normal(BaseModule):
        _name = "mod_normal"
        watched_events = ["*"]

    class mod_host_only(BaseModule):
        _name = "mod_hostonly"
        watched_events = ["*"]
        per_host_only = True

    class mod_hostport_only(BaseModule):
        _name = "mod_normal"
        watched_events = ["*"]
        per_hostport_only = True

    class mod_domain_only(BaseModule):
        _name = "domain_only"
        watched_events = ["*"]
        per_domain_only = True

    scan = bbot_scanner(
        "evilcorp.com",
        config=bbot_config,
        force_start=True,
    )

    scan.modules["mod_normal"] = mod_normal(scan)
    scan.modules["mod_host_only"] = mod_host_only(scan)
    scan.modules["mod_hostport_only"] = mod_hostport_only(scan)
    scan.modules["mod_domain_only"] = mod_domain_only(scan)
    scan.status = "RUNNING"

    url_1 = scan.make_event("http://evilcorp.com/1", event_type="URL", source=scan.root_event, tags=["status-200"])
    url_2 = scan.make_event("http://evilcorp.com/2", event_type="URL", source=scan.root_event, tags=["status-200"])
    url_3 = scan.make_event("http://evilcorp.com:888/3", event_type="URL", source=scan.root_event, tags=["status-200"])
    url_4 = scan.make_event("http://www.evilcorp.com/", event_type="URL", source=scan.root_event, tags=["status-200"])
    url_5 = scan.make_event("http://www.evilcorp.net/", event_type="URL", source=scan.root_event, tags=["status-200"])

    url_1.scope_distance = 0
    url_2.scope_distance = 0
    url_3.scope_distance = 0
    url_4.scope_distance = 0
    url_5.scope_distance = 0

    for mod_name in ("mod_normal", "mod_host_only", "mod_hostport_only", "mod_domain_only"):
        module = scan.modules[mod_name]

        valid_1, reason_1 = await module._event_postcheck(url_1)
        valid_2, reason_2 = await module._event_postcheck(url_2)
        valid_3, reason_3 = await module._event_postcheck(url_3)
        valid_4, reason_4 = await module._event_postcheck(url_4)
        valid_5, reason_5 = await module._event_postcheck(url_5)

        if mod_name == "mod_normal":
            assert valid_1 == True
            assert valid_2 == True
            assert valid_3 == True
            assert valid_4 == True
            assert valid_5 == True
        elif mod_name == "mod_host_only":
            assert valid_1 == True
            assert valid_2 == False
            assert "per_host_only=True" in reason_2
            assert valid_3 == False
            assert "per_host_only=True" in reason_3
            assert valid_4 == True
            assert valid_5 == True
        elif mod_name == "mod_hostport_only":
            assert valid_1 == True
            assert valid_2 == False
            assert "per_hostport_only=True" in reason_2
            assert valid_3 == True
            assert valid_4 == True
            assert valid_5 == True
        elif mod_name == "mod_domain_only":
            assert valid_1 == True
            assert valid_2 == False
            assert "per_domain_only=True" in reason_2
            assert valid_3 == False
            assert "per_domain_only=True" in reason_3
            assert valid_4 == False
            assert "per_domain_only=True" in reason_4
            assert valid_5 == True


@pytest.mark.asyncio
async def test_modules_basic_perdomainonly(scan, helpers, events, bbot_config, bbot_scanner, httpx_mock, monkeypatch):
    per_domain_scan = bbot_scanner(
        "evilcorp.com",
        modules=list(set(available_modules + available_internal_modules)),
        config=bbot_config,
        force_start=True,
    )

    await per_domain_scan.load_modules()
    await per_domain_scan.setup_modules()
    per_domain_scan.status = "RUNNING"

    # ensure that multiple events to the same "host" (schema + host) are blocked and check the per host tracker

    for module_name, module in sorted(per_domain_scan.modules.items()):
        monkeypatch.setattr(module, "filter_event", BaseModule(per_domain_scan).filter_event)

        if "URL" in module.watched_events:
            url_1 = per_domain_scan.make_event(
                "http://www.evilcorp.com/1", event_type="URL", source=per_domain_scan.root_event, tags=["status-200"]
            )
            url_1.scope_distance = 0
            url_2 = per_domain_scan.make_event(
                "http://mail.evilcorp.com/2", event_type="URL", source=per_domain_scan.root_event, tags=["status-200"]
            )
            url_2.scope_distance = 0
            valid_1, reason_1 = await module._event_postcheck(url_1)
            valid_2, reason_2 = await module._event_postcheck(url_2)

            if module.per_domain_only == True:
                assert valid_1 == True
                assert valid_2 == False
                assert hash("evilcorp.com") in module._per_host_tracker
                assert reason_2 == "per_domain_only enabled and already seen domain"

            else:
                assert valid_1 == True
                assert valid_2 == True


@pytest.mark.asyncio
async def test_modules_basic_stats(helpers, events, bbot_config, bbot_scanner, httpx_mock, monkeypatch, mock_dns):
    from bbot.modules.base import BaseModule

    class dummy(BaseModule):
        _name = "dummy"
        watched_events = ["*"]

        async def handle_event(self, event):
            # quick emit events like FINDINGS behave differently than normal ones
            # hosts are not speculated from them
            await self.emit_event(
                {"host": "www.evilcorp.com", "url": "http://www.evilcorp.com", "description": "asdf"}, "FINDING", event
            )
            await self.emit_event("https://asdf.evilcorp.com", "URL", event, tags=["status-200"])

    scan = bbot_scanner(
        "evilcorp.com",
        modules=["speculate"],
        config=bbot_config,
        force_start=True,
    )
    mock_dns(
        scan,
        {
            "evilcorp.com": {"A": ["127.0.254.1"]},
            "www.evilcorp.com": {"A": ["127.0.254.2"]},
            "asdf.evilcorp.com": {"A": ["127.0.254.3"]},
        },
    )

    scan.modules["dummy"] = dummy(scan)
    events = [e async for e in scan.async_start()]

    assert len(events) == 7
    assert 1 == len([e for e in events if e.type == "SCAN"])
    assert 2 == len([e for e in events if e.type == "DNS_NAME"])
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "evilcorp.com"])
    # the reason we don't have a DNS_NAME for www.evilcorp.com is because FINDING.quick_emit = True
    assert 0 == len([e for e in events if e.type == "DNS_NAME" and e.data == "www.evilcorp.com"])
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "asdf.evilcorp.com"])
    assert 1 == len([e for e in events if e.type == "ORG_STUB" and e.data == "evilcorp"])
    assert 1 == len([e for e in events if e.type == "FINDING"])
    assert 1 == len([e for e in events if e.type == "URL_UNVERIFIED"])

    assert scan.stats.events_emitted_by_type == {
        "SCAN": 1,
        "DNS_NAME": 2,
        "URL": 1,
        "URL_UNVERIFIED": 1,
        "FINDING": 1,
        "ORG_STUB": 1,
    }

    assert set(scan.stats.module_stats) == {"host", "speculate", "python", "dummy", "TARGET"}

    target_stats = scan.stats.module_stats["TARGET"]
    assert target_stats.produced == {"SCAN": 1, "DNS_NAME": 1}
    assert target_stats.produced_total == 2
    assert target_stats.consumed == {}
    assert target_stats.consumed_total == 0

    dummy_stats = scan.stats.module_stats["dummy"]
    assert dummy_stats.produced == {"FINDING": 1, "URL": 1}
    assert dummy_stats.produced_total == 2
    assert dummy_stats.consumed == {"DNS_NAME": 2, "OPEN_TCP_PORT": 1, "SCAN": 1, "URL": 1, "URL_UNVERIFIED": 1}
    assert dummy_stats.consumed_total == 6

    python_stats = scan.stats.module_stats["python"]
    assert python_stats.produced == {}
    assert python_stats.produced_total == 0
    assert python_stats.consumed == {
        "DNS_NAME": 2,
        "FINDING": 1,
        "ORG_STUB": 1,
        "SCAN": 1,
        "URL": 1,
        "URL_UNVERIFIED": 1,
    }
    assert python_stats.consumed_total == 7

    speculate_stats = scan.stats.module_stats["speculate"]
    assert speculate_stats.produced == {"URL_UNVERIFIED": 1, "ORG_STUB": 1}
    assert speculate_stats.produced_total == 2
    assert speculate_stats.consumed == {"URL": 1, "DNS_NAME": 2, "URL_UNVERIFIED": 1}
    assert speculate_stats.consumed_total == 4
