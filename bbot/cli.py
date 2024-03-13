#!/usr/bin/env python3

import sys
import asyncio
import logging
import traceback

# fix tee buffering
sys.stdout.reconfigure(line_buffering=True)

from bbot.core import CORE

from bbot import __version__
from bbot.core.helpers.logger import log_to_stderr

log = logging.getLogger("bbot.cli")

err = False
scan_name = ""


async def _main():
    from bbot.scanner import Scanner
    from bbot.scanner.preset import Preset

    # start by creating a default scan preset
    preset = Preset()
    # parse command line arguments and merge into preset
    preset.parse_args()

    # print help if no arguments
    if len(sys.argv) == 1:
        preset.args.parser.print_help()
        sys.exit(1)
        return

    # --version
    if preset.args.parsed.version:
        log.stdout(__version__)
        sys.exit(0)
        return

    # --current-preset
    if preset.args.parsed.current_preset:
        log.stdout(preset.to_yaml())
        sys.exit(0)
        return

    # --current-preset-full
    if preset.args.parsed.current_preset_full:
        log.stdout(preset.to_yaml(full_config=True))
        sys.exit(0)
        return

    # --list-modules
    if preset.args.parsed.list_modules:
        log.stdout("")
        log.stdout("### MODULES ###")
        log.stdout("")
        for row in preset.module_loader.modules_table(preset.modules).splitlines():
            log.stdout(row)
        return

    # --list-flags
    if preset.args.parsed.list_flags:
        log.stdout("")
        log.stdout("### FLAGS ###")
        log.stdout("")
        for row in preset.module_loader.flags_table(flags=preset.flags).splitlines():
            log.stdout(row)
        return

    scan = Scanner(preset=preset)

    await scan.async_start_without_generator()


def main():
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
