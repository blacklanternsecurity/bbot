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
    base_output_module = BaseOutputModule(scan)
    base_output_module.watched_events = ["IP_ADDRESS"]
    localhost = scan.make_event("127.0.0.1", source=scan.root_event)
    assert base_output_module._event_precheck(localhost)[0] == True
    localhost._internal = True
    assert base_output_module._event_precheck(localhost)[0] == False
    localhost._force_output = True
    assert base_output_module._event_precheck(localhost)[0] == True
    localhost._omit = True
    assert base_output_module._event_precheck(localhost)[0] == False

    # common event filtering tests
    for module_class in (BaseModule, BaseOutputModule, BaseReportModule, BaseInternalModule):
        base_module = module_class(scan)
        localhost2 = scan.make_event("127.0.0.2", source=events.subdomain)
        localhost2.set_scope_distance(0)
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
        # special case for IPs and ranges
        base_module.watched_events = ["IP_ADDRESS", "IP_RANGE"]
        ip_range = scan.make_event("127.0.0.0/24", dummy=True)
        localhost4 = scan.make_event("127.0.0.1", source=ip_range)
        localhost4.set_scope_distance(0)
        localhost4.module = "plumbus"
        assert base_module._event_precheck(localhost4)[0] == True
        localhost4.module = "speculate"
        assert base_module._event_precheck(localhost4)[0] == False

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
        localhost4 = scan.make_event("127.0.0.1", source=events.subdomain)
        valid, reason = await base_module._event_postcheck(events.localhost)
        assert valid

    base_output_module = BaseOutputModule(scan)
    base_output_module.watched_events = ["IP_ADDRESS"]

    scan2 = bbot_scanner(
        modules=list(set(available_modules + available_internal_modules)),
        output_modules=list(available_output_modules),
        config=bbot_config,
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
async def test_modules_basic_perhostonly(scan, helpers, events, bbot_config, bbot_scanner, httpx_mock, monkeypatch):
    per_host_scan = bbot_scanner(
        "evilcorp.com",
        modules=list(set(available_modules + available_internal_modules)),
        config=bbot_config,
    )

    await per_host_scan.load_modules()
    await per_host_scan.setup_modules()
    per_host_scan.status = "RUNNING"

    # ensure that multiple events to the same "host" (schema + host) are blocked and check the per host tracker
    for module_name, module in sorted(per_host_scan.modules.items()):
        #    module.filter_event = base_module.filter_event
        monkeypatch.setattr(module, "filter_event", BaseModule(per_host_scan).filter_event)

        if "URL" in module.watched_events:
            url_1 = per_host_scan.make_event(
                "http://evilcorp.com/1", event_type="URL", source=per_host_scan.root_event, tags=["status-200"]
            )
            url_1.set_scope_distance(0)
            url_2 = per_host_scan.make_event(
                "http://evilcorp.com/2", event_type="URL", source=per_host_scan.root_event, tags=["status-200"]
            )
            url_2.set_scope_distance(0)
            valid_1, reason_1 = await module._event_postcheck(url_1)
            valid_2, reason_2 = await module._event_postcheck(url_2)

            if module.per_host_only == True:
                assert valid_1 == True
                assert valid_2 == False
                assert hash("http://evilcorp.com/") in module._per_host_tracker

            else:
                assert valid_1 == True
                assert valid_2 == True
