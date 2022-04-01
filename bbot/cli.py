#!/usr/bin/env python3

import sys
import logging
import argparse

# logging
from bbot.core.logger import init_logging

logging_queue, logging_handlers = init_logging()

from bbot.modules import list_module_stems
from bbot.core.configurator.args import parser

log = logging.getLogger("bbot.cli")


def main():

    try:

        if len(sys.argv) == 1:
            parser.print_help()
            sys.exit(1)

        # note: command line arguments are in bbot/core/configurator/args.py
        options = parser.parse_args()
        if "all" in options.modules:
            options.modules = list(list_module_stems())

        # config test
        from . import config
        from omegaconf import OmegaConf

        if options.current_config:
            log.stdout(f"{OmegaConf.to_yaml(config)}")
            sys.exit(0)

        log.info(f'Command: {" ".join(sys.argv)}')

        # scan test
        from bbot.scanner import Scanner

        scanner = Scanner("asdf", *options.targets, modules=options.modules, config=config)
        scanner.start()

    except argparse.ArgumentError as e:
        log.error(e)
        log.error("Check your syntax")
        sys.exit(2)

    except Exception as e:
        if options.debug:
            import traceback

            log.error(traceback.format_exc())
        else:
            log.error(f"Encountered error (-d to debug): {e}")

    except KeyboardInterrupt:
        log.error("Interrupted")
        sys.exit(1)


if __name__ == "__main__":
    main()
