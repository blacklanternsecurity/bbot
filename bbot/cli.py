#!/usr/bin/env python3

import io
import os
import sys
import logging
import multiprocessing
from bbot.errors import *
from bbot import __version__
from bbot.logger import log_to_stderr
from bbot.core.helpers.misc import chain_lists


if multiprocessing.current_process().name == "MainProcess":
    # the --no-color flag is parsed later, so honor it (and the NO_COLOR env) before any color is printed
    no_color = "--no-color" in sys.argv or bool(os.environ.get("NO_COLOR", ""))
    if no_color:
        os.environ["NO_COLOR"] = "1"
    silent = "-s" in sys.argv or "--silent" in sys.argv

    if not silent:
        o = "" if no_color else "\033[1;38;5;208m"
        e = "" if no_color else "\033[0m"
        ascii_art = rf""" {o} ______ {e} _____   ____ _______
 {o}|  ___ \{e}|  __ \ / __ \__   __|
 {o}| |___) {e}| |__) | |  | | | |
 {o}|  ___ <{e}|  __ <| |  | | | |
 {o}| |___) {e}| |__) | |__| | | |
 {o}|______/{e}|_____/ \____/  |_|
 {o}BIGHUGE{e} BLS OSINT TOOL {__version__}

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
        # apply CLI log level options (e.g. --debug/--verbose/--silent) to the
        # global core logger even for CLI-only commands (like --install-all-deps)
        # that don't construct a full Scanner.
        preset.apply_log_level(apply_core=True)

        # which generated config files the user is regenerating this run
        reset_labels = [
            label
            for label, requested in (("config", options.reset_config), ("secrets", options.reset_secrets))
            if requested
        ]

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

        # --reset-config / --reset-secrets
        if reset_labels:
            reset_paths = [
                spec["path"]
                for spec in preset.module_loader._generated_config_files()
                if spec["label"] in reset_labels
            ]
            log.hugewarning(
                "Regenerating from current defaults. Any settings you have customized "
                "(uncommented) in these files WILL BE WIPED OUT:"
            )
            for p in reset_paths:
                log.warning(f"  {p}")
            log.warning("A backup of each existing file will be saved with a .bak extension.")
            try:
                stdin_is_tty = sys.stdin.isatty()
            except (ValueError, io.UnsupportedOperation):
                stdin_is_tty = False
            if not options.yes:
                if not stdin_is_tty:
                    log.error("Refusing to reset config without confirmation; re-run with --yes to proceed.")
                    sys.exit(1)
                    return
                answer = input("Continue? [y/N] ").strip().lower()
                if answer not in ("y", "yes"):
                    log.info("Aborted. No changes made.")
                    sys.exit(0)
                    return
            backups = preset.module_loader.reset_config_files(reset_labels)
            log.success("Regenerated config files from current defaults.")
            for b in backups:
                log.info(f"Backup saved: {b}")
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

            # Bake a temporary copy of the preset so that flags correctly enable their associated modules before listing them
            preset.validate()
            preset = preset.bake()

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
            preset.validate()
        except ValidationError as e:
            log.error(str(e))
            # if a bad option actually lives in one of the user's generated
            # config files (vs, say, a -c CLI typo), point them at the matching
            # reset flag -- validate each file's own contents to be sure
            import yaml
            from bbot.scanner.preset.validate import validate_preset

            for spec in preset.module_loader._generated_config_files():
                if not spec["path"].exists():
                    continue
                try:
                    file_config = yaml.safe_load(spec["path"].read_text()) or {}
                except yaml.YAMLError:
                    continue
                if isinstance(file_config, dict) and validate_preset(
                    {"config": file_config}, module_loader=preset.module_loader
                ):
                    log.warning(
                        f"Some options in {spec['path']} are not recognized. They may be left over from an "
                        f"older version of BBOT. You have the option of regenerating from current defaults "
                        f"with: bbot {spec['reset_flag']}"
                    )
            return
        baked_preset = preset.bake()

        # --current-preset / --current-preset-full
        if options.current_preset or options.current_preset_full:
            # Ensure we always have a human-friendly description. Prefer an
            # explicit scan_name if present, otherwise fall back to the
            # preset name (e.g. "bbot_cli_main").
            if not baked_preset.description:
                if baked_preset.scan_name:
                    baked_preset.description = str(baked_preset.scan_name)
                elif baked_preset.name:
                    baked_preset.description = str(baked_preset.name)
            if options.current_preset_full:
                print(baked_preset.to_yaml(full_config=True))
            else:
                print(baked_preset.to_yaml())
            sys.exit(0)
            return

        try:
            scan = Scanner(preset=baked_preset)
        except (PresetAbortError, ValidationError) as e:
            log.warning(str(e))
            return

        # --install-all-deps
        if options.install_all_deps:
            # create a throwaway Scanner solely so that Preset.bake(scan) can perform find_and_replace() on all module configs so that placeholders like "#{BBOT_TOOLS}" are resolved before running Ansible tasks.
            from bbot.scanner import Scanner as _ScannerForDeps

            preloaded_modules = preset.module_loader.preloaded()
            modules_for_deps = [
                k for k, v in preloaded_modules.items() if str(v.get("type", "")) in ("scan", "output")
            ]

            # dummy scan used only for environment preparation
            dummy_scan = _ScannerForDeps(preset=preset)

            helper = dummy_scan.helpers
            log.info("Installing module dependencies")
            succeeded, failed = await helper.depsinstaller.install(*modules_for_deps)
            if succeeded:
                log.success(
                    f"Successfully installed dependencies for {len(succeeded):,} modules: {','.join(succeeded)}"
                )
            if failed:
                log.warning(f"Failed to install dependencies for {len(failed):,} modules: {', '.join(failed)}")
                return False
            return True

        await scan._prep()

        log.verbose("")
        log.verbose("### MODULES ENABLED ###")
        log.verbose("")
        for row in scan.preset.module_loader.modules_table(scan.preset.modules).splitlines():
            log.verbose(row)

        scan.helpers.word_cloud.load()

        scan_name = str(scan.name)

        if not options.dry_run:
            log.trace(f"Command: {' '.join(sys.argv)}")

            # In some environments (e.g. tests) stdin may be closed or not support isatty(). Treat those cases as non-interactive.
            try:
                stdin_is_tty = sys.stdin.isatty()
            except (ValueError, io.UnsupportedOperation):
                stdin_is_tty = False

            if stdin_is_tty:
                # warn if any targets belong directly to a cloud provider
                if not scan.preset.strict_scope:
                    from cloudcheck import CloudCheckError

                    for event in scan.target.seeds.event_seeds:
                        if event.type == "DNS_NAME":
                            # a cloudcheck failure here (e.g. signatures couldn't be
                            # fetched) shouldn't abort the scan — this is only a
                            # pre-scan heads-up, so warn and move on
                            try:
                                cloudcheck_result = await scan.helpers.cloudcheck.lookup(event.host)
                            except CloudCheckError as e:
                                scan.warning(f"Unable to check whether {event.host} is a cloud domain: {e}")
                                cloudcheck_result = None
                            if cloudcheck_result:
                                scan.hugewarning(
                                    f'YOUR TARGET CONTAINS A CLOUD DOMAIN: "{event.host}". You\'re in for a wild ride!'
                                )

                # warn about loud/invasive modules
                loud_modules = []
                invasive_modules = []
                for m in scan.preset.scan_modules:
                    flags = scan.preset.preloaded_module(m).get("flags", [])
                    if "loud" in flags:
                        loud_modules.append(m)
                    if "invasive" in flags:
                        invasive_modules.append(m)
                if loud_modules:
                    log.hugewarning(
                        f"LOUD modules enabled: {','.join(loud_modules)}. These generate a lot of traffic. To exclude, use -ef loud"
                    )
                if invasive_modules:
                    log.hugewarning(
                        f"INVASIVE modules enabled: {','.join(invasive_modules)}. These may be intrusive or destructive. To exclude, use -ef invasive"
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

    log = logging.getLogger("bbot.cli")

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
        log.warning(msg)
        log.trace(traceback.format_exc())
        log_to_stderr(msg, level="WARNING")
        if CORE.logger.log_level <= logging.DEBUG:
            log_to_stderr(traceback.format_exc(), level="DEBUG")
        exit(1)
    except Exception as e:
        log.error(f"Unhandled exception: {e}")
        log.trace(traceback.format_exc())
        log_to_stderr(f"Unhandled exception: {e}", level="CRITICAL")
        log_to_stderr(traceback.format_exc(), level="DEBUG")
        exit(1)


if __name__ == "__main__":
    main()
