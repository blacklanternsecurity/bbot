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

        log.info(f'Command: {" ".join(sys.argv)}')
        # note: command line arguments are in bbot/core/configurator/args.py
        options = parser.parse_args()
        if "all" in options.modules:
            options.modules = list(list_module_stems())

        # config test
        from . import config
        from omegaconf import OmegaConf

        log.info(f"Config:\n{OmegaConf.to_yaml(config)}")

        # scan test
        from bbot.scanner import Scanner

        scanner = Scanner(
            "asdf", *options.targets, modules=options.modules, config=config
        )
        scanner.start()

    except argparse.ArgumentError as e:
        log.error(e)
        log.error("Check your syntax")
        sys.exit(2)

    except Exception as e:
        if options.verbose:
            import traceback

            log.error(traceback.format_exc())
        else:
            log.error(f"Encountered error (-v to debug): {e}")

    except KeyboardInterrupt:
        log.error("Interrupted")
        sys.exit(1)


if __name__ == "__main__":
    main()
