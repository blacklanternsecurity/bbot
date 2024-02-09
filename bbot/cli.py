#!/usr/bin/env python3

import sys
import asyncio
import logging
import traceback
from bbot.core.helpers.logger import log_to_stderr

# fix tee buffering
sys.stdout.reconfigure(line_buffering=True)

log = logging.getLogger("bbot.cli")
sys.stdout.reconfigure(line_buffering=True)


from bbot.core import CORE


async def _main():
    CORE.args
    CORE.module_loader.preloaded()


def main():
    try:
        asyncio.run(_main())
    except asyncio.CancelledError:
        if CORE.logger.log_level <= logging.DEBUG:
            log_to_stderr(traceback.format_exc(), level="DEBUG")
    except KeyboardInterrupt:
        msg = "Interrupted"
        log_to_stderr(msg, level="WARNING")
        if CORE.logger.log_level <= logging.DEBUG:
            log_to_stderr(traceback.format_exc(), level="DEBUG")
        exit(1)


if __name__ == "__main__":
    main()
