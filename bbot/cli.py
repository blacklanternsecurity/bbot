#!/usr/bin/env python3

import io
import sys
import logging
import multiprocessing
from bbot.errors import *
from bbot import __version__
from bbot.logger import log_to_stderr
from bbot.core.helpers.misc import chain_lists


if multiprocessing.current_process().name == "MainProcess":
    silent = "-s" in sys.argv or "--silent" in sys.argv

    if not silent:
        ascii_art = rf""" [1;38;5;208m ______ [0m _____   ____ _______
 [1;38;5;208m|  ___ \[0m|  __ \ / __ \__   __|
 [1;38;5;208m| |___) [0m| |__) | |  | | | |
 [1;38;5;208m|  ___ <[0m|  __ <| |  | | | |
 [1;38;5;208m| |___) [0m| |__) | |__| | | |
 [1;38;5;208m|______/[0m|_____/ \____/  |_|
 [1;38;5;208mBIGHUGE[0m BLS OSINT TOOL {__version__}

www.blacklanternsecurity.com/bbot
"""
        print(ascii_art, file=sys.stderr)

scan_name = ""


async def _main():
    import asyncio
    import traceback
    from contextlib import suppress

    # fix tee buffering
    sys.stdout.reconfigure(line_buffering=True)

    log = logging.getLogger("bbot.cli")

    from bbot.scanner import Scanner
    from bbot.scanner.preset import Preset

    global scan_name

    try:
        # start by creating a default scan preset
        preset = Preset(_log=True, name="bbot_cli_main")
        # parse command line arguments and merge into preset
        try:
            preset.parse_args()
        except BBOTArgumentError as e:
            log_to_stderr(str(e), level="WARNING")
            log.trace(traceback.format_exc())
            return
        # ensure arguments (-c config options etc.) are valid
        options = preset.args.parsed

        # print help if no arguments
        if len(sys.argv) == 1:
            print(preset.args.parser.format_help())
            sys.exit(1)
            return

        # --version
        if options.version:
            print(__version__)
            sys.exit(0)
            return

        # --list-presets
        if options.list_presets:
            print("")
            print("### PRESETS ###")
            print("")
            for row in preset.presets_table().splitlines():
                print(row)
            return

        # if we're listing modules or their options
        if options.list_modules or options.list_output_modules or options.list_module_options or options.module_help:
            # if no modules or flags are specified, enable everything
            if not (options.modules or options.output_modules or options.flags):
                for module, preloaded in preset.module_loader.preloaded().items():
                    module_type = preloaded.get("type", "scan")
                    preset.add_module(module, module_type=module_type)

            if options.modules or options.output_modules or options.flags:
                preset._default_output_modules = options.output_modules
                preset._default_internal_modules = []

            preset.bake()

            # --list-modules
            if options.list_modules:
                print("")
                print("### MODULES ###")
                print("")
                modules = sorted(set(preset.scan_modules + preset.internal_modules))
                for row in preset.module_loader.modules_table(modules).splitlines():
                    print(row)
                return

            # --list-output-modules
            if options.list_output_modules:
                print("")
                print("### OUTPUT MODULES ###")
                print("")
                for row in preset.module_loader.modules_table(preset.output_modules).splitlines():
                    print(row)
                return

            # --list-module-options
            if options.list_module_options:
                print("")
                print("### MODULE OPTIONS ###")
                print("")
                for row in preset.module_loader.modules_options_table(preset.modules).splitlines():
                    print(row)
                return

            # --module-help
            if options.module_help:
                module_name = options.module_help
                all_modules = list(preset.module_loader.preloaded())
                if module_name not in all_modules:
                    log.hugewarning(f'Module "{module_name}" not found')
                    return

                # Load the module class
                loaded_modules = preset.module_loader.load_modules([module_name])
                module_name, module_class = next(iter(loaded_modules.items()))
                print(module_class.help_text())
                return

        # --list-flags
        if options.list_flags:
            flags = preset.flags if preset.flags else None
            print("")
            print("### FLAGS ###")
            print("")
            for row in preset.module_loader.flags_table(flags=flags).splitlines():
                print(row)
            return

        try:
            scan = Scanner(preset=preset)
        except (PresetAbortError, ValidationError) as e:
            log.warning(str(e))
            return

        deadly_modules = [
            m for m in scan.preset.scan_modules if "deadly" in preset.preloaded_module(m).get("flags", [])
        ]
        if deadly_modules and not options.allow_deadly:
            log.hugewarning(f"You enabled the following deadly modules: {','.join(deadly_modules)}")
            log.hugewarning("Deadly modules are highly intrusive")
            log.hugewarning("Please specify --allow-deadly to continue")
            return False

        # --current-preset
        if options.current_preset:
            print(scan.preset.to_yaml())
            sys.exit(0)
            return

        # --current-preset-full
        if options.current_preset_full:
            print(scan.preset.to_yaml(full_config=True))
            sys.exit(0)
            return

        # --install-all-deps
        if options.install_all_deps:
            all_modules = list(preset.module_loader.preloaded())
            scan.helpers.depsinstaller.force_deps = True
            succeeded, failed = await scan.helpers.depsinstaller.install(*all_modules)
            if failed:
                log.hugewarning(f"Failed to install dependencies for the following modules: {', '.join(failed)}")
                return False
            log.hugesuccess(f"Successfully installed dependencies for the following modules: {', '.join(succeeded)}")
            return True

        scan_name = str(scan.name)

        log.verbose("")
        log.verbose("### MODULES ENABLED ###")
        log.verbose("")
        for row in scan.preset.module_loader.modules_table(scan.preset.modules).splitlines():
            log.verbose(row)

        scan.helpers.word_cloud.load()
        await scan._prep()

        if not options.dry_run:
            log.trace(f"Command: {' '.join(sys.argv)}")

            if sys.stdin.isatty():
                # warn if any targets belong directly to a cloud provider
                if not scan.preset.strict_scope:
                    for event in scan.target.seeds.events:
                        if event.type == "DNS_NAME":
                            cloudcheck_result = scan.helpers.cloudcheck(event.host)
                            if cloudcheck_result:
                                scan.hugewarning(
                                    f'YOUR TARGET CONTAINS A CLOUD DOMAIN: "{event.host}". You\'re in for a wild ride!'
                                )

                if not options.yes:
                    log.hugesuccess(f"Scan ready. Press enter to execute {scan.name}")
                    input()

                import os
                import re
                import fcntl
                from bbot.core.helpers.misc import smart_decode

                def handle_keyboard_input(keyboard_input):
                    kill_regex = re.compile(r"kill (?P<modules>[a-z0-9_ ,]+)")
                    if keyboard_input:
                        log.verbose(f'Got keyboard input: "{keyboard_input}"')
                        kill_match = kill_regex.match(keyboard_input)
                        if kill_match:
                            modules = kill_match.group("modules")
                            if modules:
                                modules = chain_lists(modules)
                                for module in modules:
                                    if module in scan.modules:
                                        log.hugewarning(f'Killing module: "{module}"')
                                        scan.kill_module(module, message="killed by user")
                                    else:
                                        log.warning(f'Invalid module: "{module}"')
                    else:
                        scan.preset.core.logger.toggle_log_level(logger=log)
                        scan.modules_status(_log=True)

                reader = asyncio.StreamReader()
                protocol = asyncio.StreamReaderProtocol(reader)
                await asyncio.get_running_loop().connect_read_pipe(lambda: protocol, sys.stdin)

                # set stdout and stderr to blocking mode
                # this is needed to prevent BlockingIOErrors in logging etc.
                fds = []
                for stream in [sys.stdout, sys.stderr]:
                    try:
                        fds.append(stream.fileno())
                    except io.UnsupportedOperation:
                        log.debug(f"Can't get fileno for {stream}")
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

                keyboard_listen_task = asyncio.create_task(akeyboard_listen())  # noqa F841

            await scan.async_start_without_generator()

        return True

    except BBOTError as e:
        log.error(str(e))
        log.trace(traceback.format_exc())

    finally:
        # save word cloud
        with suppress(BaseException):
            scan.helpers.word_cloud.save()
        # remove output directory if empty
        with suppress(BaseException):
            scan.home.rmdir()


def main():
    import asyncio
    import traceback
    from bbot.core import CORE

    global scan_name
    try:
        asyncio.run(_main())
    except asyncio.CancelledError:
        if CORE.logger.log_level <= logging.DEBUG:
            log_to_stderr(traceback.format_exc(), level="DEBUG")
    except KeyboardInterrupt:
        msg = "Interrupted"
        if scan_name:
            msg = f"You killed {scan_name}"
        log_to_stderr(msg, level="WARNING")
        if CORE.logger.log_level <= logging.DEBUG:
            log_to_stderr(traceback.format_exc(), level="DEBUG")
        exit(1)


if __name__ == "__main__":
    main()
