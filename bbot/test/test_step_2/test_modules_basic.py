import re
import requests_mock

from ..bbot_fixtures import *


def test_modules_basic(patch_commands, patch_ansible, scan, helpers, events, bbot_config, bbot_scanner):
    fallback_nameservers = scan.helpers.temp_dir / "nameservers.txt"
    with open(fallback_nameservers, "w") as f:
        f.write("8.8.8.8\n")

    with requests_mock.Mocker() as m:
        for http_method in ("GET", "CONNECT", "HEAD", "POST", "PUT", "TRACE", "DEBUG", "PATCH", "DELETE", "OPTIONS"):
            m.request(http_method, re.compile(r".*"), text='{"test": "test"}')

        # event filtering
        from bbot.modules.base import BaseModule
        from bbot.modules.output.base import BaseOutputModule
        from bbot.modules.report.base import BaseReportModule
        from bbot.modules.internal.base import BaseInternalModule

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
            localhost2.make_in_scope()
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
            localhost2.tags.add("target")
            assert base_module._event_precheck(localhost2)[0] == True
            base_module.target_only = False
            # special case for IPs and ranges
            base_module.watched_events = ["IP_ADDRESS", "IP_RANGE"]
            ip_range = scan.make_event("127.0.0.0/24", dummy=True)
            localhost4 = scan.make_event("127.0.0.1", source=ip_range)
            localhost4.make_in_scope()
            localhost4.module = "plumbus"
            assert base_module._event_precheck(localhost4)[0] == True
            localhost4.module = "speculate"
            assert base_module._event_precheck(localhost4)[0] == False

            # in scope only
            localhost3 = scan.make_event("127.0.0.2", source=events.subdomain)
            base_module.in_scope_only = True
            assert base_module._event_postcheck(events.localhost)[0] == True
            assert base_module._event_postcheck(localhost3)[0] == False
            base_module.in_scope_only = False
            # scope distance
            base_module.scope_distance_modifier = 0
            localhost2._scope_distance = 0
            assert base_module._event_postcheck(localhost2)[0] == True
            localhost2._scope_distance = 1
            assert base_module._event_postcheck(localhost2)[0] == True
            localhost2._scope_distance = 2
            assert base_module._event_postcheck(localhost2)[0] == False
            localhost2._scope_distance = -1
            assert base_module._event_postcheck(localhost2)[0] == False
            base_module.scope_distance_modifier = -1

        base_output_module = BaseOutputModule(scan)
        base_output_module.watched_events = ["IP_ADDRESS"]

        scan2 = bbot_scanner(
            modules=list(set(available_modules + available_internal_modules)),
            output_modules=list(available_output_modules),
            config=bbot_config,
        )
        scan2.helpers.dns.fallback_nameservers_file = fallback_nameservers
        patch_commands(scan2)
        patch_ansible(scan2)
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
                assert preloaded.get("meta", {}).get("description", ""), f"{module_name} must have a description"

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
            assert type(preloaded.get("config", None)) == dict, f"{module_name}.options must be of type list"
            assert (
                type(preloaded.get("options_desc", None)) == dict
            ), f"{module_name}.options_desc must be of type list"
            # options must have descriptions
            assert set(preloaded.get("config", {})) == set(
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
            future = scan2._thread_pool.submit(module.setup)
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
            module._filter = lambda *args, **kwargs: True, ""
            events_to_submit = [e for e in events.all if e.type in module.watched_events]
            if module.batch_size > 1:
                log.info(f"Testing {module_name}.handle_batch()")
                future = scan2._thread_pool.submit(module.handle_batch, *events_to_submit)
                futures[future] = module
            else:
                for e in events_to_submit:
                    log.info(f"Testing {module_name}.handle_event()")
                    future = scan2._thread_pool.submit(module.handle_event, e)
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
            future = scan2._thread_pool.submit(module.finish)
            futures[future] = module
        for future in helpers.as_completed(futures):
            assert future.result() == None
        futures.clear()

        # cleanups
        futures = {}
        for module_name, module in scan2.modules.items():
            log.info(f"Testing {module_name}.cleanup()")
            future = scan2._thread_pool.submit(module.cleanup)
            futures[future] = module
        for future in helpers.as_completed(futures):
            assert future.result() == None
        futures.clear()

        # event filters
        for module_name, module in scan2.modules.items():
            log.info(f"Testing {module_name}.filter_event()")
            assert module.filter_event(events.emoji) in (
                True,
                False,
            ), f"{module_name}.filter_event() must return either True or False"
