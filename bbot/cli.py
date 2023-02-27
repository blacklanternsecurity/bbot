#!/usr/bin/env python3

import os
import sys
import logging
import threading
import traceback
from omegaconf import OmegaConf
from contextlib import suppress

# fix tee buffering
sys.stdout.reconfigure(line_buffering=True)

# logging
from bbot.core.logger import init_logging, get_log_level, toggle_log_level

logging_queue, logging_handlers = init_logging()

import bbot.core.errors
from bbot import __version__
from bbot.modules import module_loader
from bbot.core.configurator.args import parser
from bbot.core.helpers.logger import log_to_stderr
from bbot.core.configurator import ensure_config_files

log = logging.getLogger("bbot.cli")
sys.stdout.reconfigure(line_buffering=True)


log_level = get_log_level()


from . import config


def main():
    err = False
    scan_name = ""

    ensure_config_files()

    try:
        if len(sys.argv) == 1:
            parser.print_help()
            sys.exit(1)

        # note: command line arguments are in bbot/core/configurator/args.py
        try:
            options = parser.parse_args()
        except bbot.core.errors.ArgumentError as e:
            log.warning(e)
            sys.exit(1)
            # this is intentional since sys.exit() is monkeypatched in the tests
            return

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

        log.verbose(f'Command: {" ".join(sys.argv)}')

        if options.agent_mode:
            from bbot.agent import Agent

            agent = Agent(config)
            success = agent.setup()
            if success:
                agent.start()

        else:
            from bbot.scanner import Scanner

            try:
                module_filtering = False
                if (options.list_modules or options.help_all) and not any([options.flags, options.modules]):
                    module_filtering = True
                    modules = set(module_loader.preloaded(type="scan"))
                else:
                    modules = set(options.modules)
                    # enable modules by flags
                    for m, c in module_loader.preloaded().items():
                        if m not in modules:
                            flags = c.get("flags", [])
                            if "deadly" in flags:
                                continue
                            for f in options.flags:
                                if f in flags:
                                    log.verbose(f'Enabling {m} because it has flag "{f}"')
                                    modules.add(m)

                default_output_modules = ["human", "json", "csv"]

                # Make a list of the modules which can be output to the console
                consoleable_output_modules = [
                    k for k, v in module_loader.preloaded(type="output").items() if "console" in v["config"]
                ]

                # If no options are specified, use the default set
                if not options.output_modules:
                    options.output_modules = default_output_modules

                # if none of the output modules provided on the command line are consoleable, don't turn off the defaults. Instead, just add the one specified to the defaults.
                elif not any(o in consoleable_output_modules for o in options.output_modules):
                    options.output_modules += default_output_modules

                scanner = Scanner(
                    *options.targets,
                    modules=list(modules),
                    output_modules=options.output_modules,
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
                    scanner.helpers.depsinstaller.install(*all_modules)
                    log.info("Finished installing module dependencies")
                    return

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
                        modules.remove(m)

                # excluded flags
                for m in scanner._scan_modules:
                    flags = module_loader._preloaded.get(m, {}).get("flags", [])
                    if any(f in flags for f in options.exclude_flags):
                        log.verbose(f"Removing {m} because of excluded flag: {','.join(options.exclude_flags)}")
                        modules.remove(m)

                # excluded modules
                for m in options.exclude_modules:
                    if m in modules:
                        log.verbose(f"Removing {m} because it is excluded")
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

                if options.list_modules or options.help_all:
                    return

                module_list = module_loader.filter_modules(modules=modules)
                deadly_modules = [
                    m[0] for m in module_list if "deadly" in m[-1]["flags"] and m[0] in scanner._scan_modules
                ]
                if scanner._scan_modules and deadly_modules:
                    if not options.allow_deadly:
                        log.hugewarning(f"You enabled the following deadly modules: {','.join(deadly_modules)}")
                        log.hugewarning(f"Deadly modules are highly intrusive")
                        log.hugewarning(f"Please specify --allow-deadly to continue")
                        return

                scanner.helpers.word_cloud.load(options.load_wordcloud)

                scanner.prep()

                if not options.dry_run:
                    if not options.agent_mode and not options.yes and sys.stdin.isatty():
                        log.hugesuccess(f"Scan ready. Press enter to execute {scanner.name}")
                        input()

                    def keyboard_listen():
                        while 1:
                            keyboard_input = input()
                            if not keyboard_input:
                                toggle_log_level(logger=log)

                    keyboard_listen_thread = threading.Thread(target=keyboard_listen, daemon=True)
                    keyboard_listen_thread.start()

                    scanner.start_without_generator()

            except bbot.core.errors.ScanError as e:
                log_to_stderr(str(e), level="ERROR")
            except Exception:
                raise
            finally:
                with suppress(NameError):
                    scanner.cleanup()

    except bbot.core.errors.BBOTError as e:
        log_to_stderr(f"{e} (--debug for details)", level="ERROR")
        if log_level <= logging.DEBUG:
            log_to_stderr(traceback.format_exc(), level="DEBUG")
        err = True

    except Exception:
        log_to_stderr(f"Encountered unknown error: {traceback.format_exc()}", level="ERROR")
        err = True

    except KeyboardInterrupt:
        msg = "Interrupted"
        if scan_name:
            msg = f"You killed {scan_name}"
        log_to_stderr(msg, level="ERROR")
        err = True

    finally:
        # save word cloud
        with suppress(BaseException):
            save_success, filename = scanner.helpers.word_cloud.save(options.save_wordcloud)
            if save_success:
                log_to_stderr(f"Saved word cloud ({len(scanner.helpers.word_cloud):,} words) to {filename}")
        # remove output directory if empty
        with suppress(BaseException):
            scanner.home.rmdir()
        if err:
            os._exit(1)

        # debug troublesome modules
        """
        from time import sleep
        while 1:
            scanner.manager.modules_status(_log=True)
            sleep(1)
        """


if __name__ == "__main__":
    main()
