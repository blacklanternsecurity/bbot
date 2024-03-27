#!/usr/bin/env python3

import os
import re
import sys
import asyncio
import logging
import traceback
from omegaconf import OmegaConf
from contextlib import suppress

# fix tee buffering
sys.stdout.reconfigure(line_buffering=True)

# logging
from bbot.core.logger import get_log_level, toggle_log_level

import bbot.core.errors
from bbot import __version__
from bbot.modules import module_loader
from bbot.core.configurator.args import parser
from bbot.core.helpers.logger import log_to_stderr
from bbot.core.configurator import ensure_config_files, check_cli_args, environ

log = logging.getLogger("bbot.cli")


log_level = get_log_level()


from . import config


err = False
scan_name = ""


async def _main():
    global err
    global scan_name
    environ.cli_execution = True

    # async def monitor_tasks():
    #     in_row = 0
    #     while 1:
    #         try:
    #             print('looooping')
    #             tasks = asyncio.all_tasks()
    #             current_task = asyncio.current_task()
    #             if len(tasks) == 1 and list(tasks)[0] == current_task:
    #                 print('no tasks')
    #                 in_row += 1
    #             else:
    #                 in_row = 0
    #             for t in tasks:
    #                 print(t)
    #             if in_row > 2:
    #                 break
    #             await asyncio.sleep(1)
    #         except BaseException as e:
    #             print(traceback.format_exc())
    #             with suppress(BaseException):
    #                 await asyncio.sleep(.1)

    # monitor_tasks_task = asyncio.create_task(monitor_tasks())

    ensure_config_files()

    try:
        if len(sys.argv) == 1:
            parser.print_help()
            sys.exit(1)

        options = parser.parse_args()
        check_cli_args()

        # --version
        if options.version:
            log.stdout(__version__)
            sys.exit(0)
            return

        # --current-config
        if options.current_config:
            log.stdout(f"{OmegaConf.to_yaml(config)}")
            sys.exit(0)
            return

        if options.agent_mode:
            from bbot.agent import Agent

            agent = Agent(config)
            success = agent.setup()
            if success:
                await agent.start()

        else:
            from bbot.scanner import Scanner

            try:
                output_modules = set(options.output_modules)
                module_filtering = False
                if (options.list_modules or options.help_all) and not any([options.flags, options.modules]):
                    module_filtering = True
                    modules = set(module_loader.preloaded(type="scan"))
                else:
                    modules = set(options.modules)
                    # enable modules by flags
                    for m, c in module_loader.preloaded().items():
                        module_type = c.get("type", "scan")
                        if m not in modules:
                            flags = c.get("flags", [])
                            if "deadly" in flags:
                                continue
                            for f in options.flags:
                                if f in flags:
                                    log.verbose(f'Enabling {m} because it has flag "{f}"')
                                    if module_type == "output":
                                        output_modules.add(m)
                                    else:
                                        modules.add(m)

                default_output_modules = ["human", "json", "csv"]

                # Make a list of the modules which can be output to the console
                consoleable_output_modules = [
                    k for k, v in module_loader.preloaded(type="output").items() if "console" in v["config"]
                ]

                # if none of the output modules provided on the command line are consoleable, don't turn off the defaults. Instead, just add the one specified to the defaults.
                if not any(o in consoleable_output_modules for o in output_modules):
                    output_modules.update(default_output_modules)

                scanner = Scanner(
                    *options.targets,
                    modules=list(modules),
                    output_modules=list(output_modules),
                    output_dir=options.output_dir,
                    config=config,
                    name=options.name,
                    whitelist=options.whitelist,
                    blacklist=options.blacklist,
                    strict_scope=options.strict_scope,
                    force_start=options.force,
                )

                if options.install_all_deps:
                    all_modules = list(module_loader.preloaded())
                    scanner.helpers.depsinstaller.force_deps = True
                    succeeded, failed = await scanner.helpers.depsinstaller.install(*all_modules)
                    log.info("Finished installing module dependencies")
                    return False if failed else True

                scan_name = str(scanner.name)

                # enable modules by dependency
                # this is only a basic surface-level check
                # todo: recursive dependency graph with networkx or topological sort?
                all_modules = list(set(scanner._scan_modules + scanner._internal_modules + scanner._output_modules))
                while 1:
                    changed = False
                    dep_choices = module_loader.recommend_dependencies(all_modules)
                    if not dep_choices:
                        break
                    for event_type, deps in dep_choices.items():
                        if event_type in ("*", "all"):
                            continue
                        # skip resolving dependency if a target provides the missing type
                        if any(e.type == event_type for e in scanner.target.events):
                            continue
                        required_by = deps.get("required_by", [])
                        recommended = deps.get("recommended", [])
                        if not recommended:
                            log.hugewarning(
                                f"{len(required_by):,} modules ({','.join(required_by)}) rely on {event_type} but no modules produce it"
                            )
                        elif len(recommended) == 1:
                            log.verbose(
                                f"Enabling {next(iter(recommended))} because {len(required_by):,} modules ({','.join(required_by)}) rely on it for {event_type}"
                            )
                            all_modules = list(set(all_modules + list(recommended)))
                            scanner._scan_modules = list(set(scanner._scan_modules + list(recommended)))
                            changed = True
                        else:
                            log.hugewarning(
                                f"{len(required_by):,} modules ({','.join(required_by)}) rely on {event_type} but no enabled module produces it"
                            )
                            log.hugewarning(
                                f"Recommend enabling one or more of the following modules which produce {event_type}:"
                            )
                            for m in recommended:
                                log.warning(f" - {m}")
                    if not changed:
                        break

                # required flags
                modules = set(scanner._scan_modules)
                for m in scanner._scan_modules:
                    flags = module_loader._preloaded.get(m, {}).get("flags", [])
                    if not all(f in flags for f in options.require_flags):
                        log.verbose(
                            f"Removing {m} because it does not have the required flags: {'+'.join(options.require_flags)}"
                        )
                        with suppress(KeyError):
                            modules.remove(m)

                # excluded flags
                for m in scanner._scan_modules:
                    flags = module_loader._preloaded.get(m, {}).get("flags", [])
                    if any(f in flags for f in options.exclude_flags):
                        log.verbose(f"Removing {m} because of excluded flag: {','.join(options.exclude_flags)}")
                        with suppress(KeyError):
                            modules.remove(m)

                # excluded modules
                for m in options.exclude_modules:
                    if m in modules:
                        log.verbose(f"Removing {m} because it is excluded")
                        with suppress(KeyError):
                            modules.remove(m)
                scanner._scan_modules = list(modules)

                log_fn = log.info
                if options.list_modules or options.help_all:
                    log_fn = log.stdout

                help_modules = list(modules)
                if module_filtering:
                    help_modules = None

                if options.help_all:
                    log_fn(parser.format_help())

                if options.list_flags:
                    log.stdout("")
                    log.stdout("### FLAGS ###")
                    log.stdout("")
                    for row in module_loader.flags_table(flags=options.flags).splitlines():
                        log.stdout(row)
                    return

                log_fn("")
                log_fn("### MODULES ###")
                log_fn("")
                for row in module_loader.modules_table(modules=help_modules).splitlines():
                    log_fn(row)

                if options.help_all:
                    log_fn("")
                    log_fn("### MODULE OPTIONS ###")
                    log_fn("")
                    for row in module_loader.modules_options_table(modules=help_modules).splitlines():
                        log_fn(row)

                if options.list_modules or options.list_flags or options.help_all:
                    return

                module_list = module_loader.filter_modules(modules=modules)
                deadly_modules = []
                active_modules = []
                active_aggressive_modules = []
                slow_modules = []
                for m in module_list:
                    if m[0] in scanner._scan_modules:
                        if "deadly" in m[-1]["flags"]:
                            deadly_modules.append(m[0])
                        if "active" in m[-1]["flags"]:
                            active_modules.append(m[0])
                            if "aggressive" in m[-1]["flags"]:
                                active_aggressive_modules.append(m[0])
                        if "slow" in m[-1]["flags"]:
                            slow_modules.append(m[0])
                if scanner._scan_modules:
                    if deadly_modules and not options.allow_deadly:
                        log.hugewarning(f"You enabled the following deadly modules: {','.join(deadly_modules)}")
                        log.hugewarning(f"Deadly modules are highly intrusive")
                        log.hugewarning(f"Please specify --allow-deadly to continue")
                        return False
                    if active_modules:
                        if active_modules:
                            if active_aggressive_modules:
                                log.hugewarning(
                                    "This is an (aggressive) active scan! Intrusive connections will be made to target"
                                )
                            else:
                                log.hugewarning(
                                    "This is a (safe) active scan. Non-intrusive connections will be made to target"
                                )
                    else:
                        log.hugeinfo("This is a passive scan. No connections will be made to target")
                    if slow_modules:
                        log.warning(
                            f"You have enabled the following slow modules: {','.join(slow_modules)}. Scan may take a while"
                        )

                scanner.helpers.word_cloud.load()

                await scanner._prep()

                if not options.dry_run:
                    log.trace(f"Command: {' '.join(sys.argv)}")

                    # if we're on the terminal, enable keyboard interaction
                    if sys.stdin.isatty():

                        import fcntl
                        from bbot.core.helpers.misc import smart_decode

                        if not options.agent_mode and not options.yes:
                            log.hugesuccess(f"Scan ready. Press enter to execute {scanner.name}")
                            input()

                        def handle_keyboard_input(keyboard_input):
                            kill_regex = re.compile(r"kill (?P<module>[a-z0-9_]+)")
                            if keyboard_input:
                                log.verbose(f'Got keyboard input: "{keyboard_input}"')
                                kill_match = kill_regex.match(keyboard_input)
                                if kill_match:
                                    module = kill_match.group("module")
                                    if module in scanner.modules:
                                        log.hugewarning(f'Killing module: "{module}"')
                                        scanner.manager.kill_module(module, message="killed by user")
                                    else:
                                        log.warning(f'Invalid module: "{module}"')
                            else:
                                toggle_log_level(logger=log)
                                scanner.manager.modules_status(_log=True)

                        reader = asyncio.StreamReader()
                        protocol = asyncio.StreamReaderProtocol(reader)
                        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

                        # set stdout and stderr to blocking mode
                        # this is needed to prevent BlockingIOErrors in logging etc.
                        fds = [sys.stdout.fileno(), sys.stderr.fileno()]
                        for fd in fds:
                            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
                            fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)

                        async def akeyboard_listen():
                            try:
                                allowed_errors = 10
                                while 1:
                                    keyboard_input = None
                                    try:
                                        keyboard_input = smart_decode((await reader.readline()).strip())
                                        allowed_errors = 10
                                    except Exception as e:
                                        log_to_stderr(f"Error in keyboard listen loop: {e}", level="TRACE")
                                        log_to_stderr(traceback.format_exc(), level="TRACE")
                                        allowed_errors -= 1
                                    if keyboard_input is not None:
                                        handle_keyboard_input(keyboard_input)
                                    if allowed_errors <= 0:
                                        break
                            except Exception as e:
                                log_to_stderr(f"Error in keyboard listen task: {e}", level="ERROR")
                                log_to_stderr(traceback.format_exc(), level="TRACE")

                        asyncio.create_task(akeyboard_listen())

                    await scanner.async_start_without_generator()

            except bbot.core.errors.ScanError as e:
                log_to_stderr(str(e), level="ERROR")
            except Exception:
                raise

    except bbot.core.errors.BBOTError as e:
        log_to_stderr(f"{e} (--debug for details)", level="ERROR")
        if log_level <= logging.DEBUG:
            log_to_stderr(traceback.format_exc(), level="DEBUG")
        err = True

    except Exception:
        log_to_stderr(f"Encountered unknown error: {traceback.format_exc()}", level="ERROR")
        err = True

    finally:
        # save word cloud
        with suppress(BaseException):
            save_success, filename = scanner.helpers.word_cloud.save()
            if save_success:
                log_to_stderr(f"Saved word cloud ({len(scanner.helpers.word_cloud):,} words) to {filename}")
        # remove output directory if empty
        with suppress(BaseException):
            scanner.home.rmdir()
        if err:
            os._exit(1)


def main():
    global scan_name
    try:
        asyncio.run(_main())
    except asyncio.CancelledError:
        if get_log_level() <= logging.DEBUG:
            log_to_stderr(traceback.format_exc(), level="DEBUG")
    except KeyboardInterrupt:
        msg = "Interrupted"
        if scan_name:
            msg = f"You killed {scan_name}"
        log_to_stderr(msg, level="WARNING")
        if get_log_level() <= logging.DEBUG:
            log_to_stderr(traceback.format_exc(), level="DEBUG")
        exit(1)


if __name__ == "__main__":
    main()
