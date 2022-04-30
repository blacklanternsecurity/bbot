#!/usr/bin/env python3

import sys
import logging

# fix tee buffering
sys.stdout.reconfigure(line_buffering=True)

# logging
from bbot.core.logger import init_logging

logging_queue, logging_handlers = init_logging()

import bbot.core.errors
from bbot.core.configurator.args import parser

log = logging.getLogger("bbot.cli")
sys.stdout.reconfigure(line_buffering=True)


def main():

    try:

        if len(sys.argv) == 1:
            parser.print_help()
            sys.exit(1)

        # note: command line arguments are in bbot/core/configurator/args.py
        options = parser.parse_args()

        # config test
        from . import config
        from omegaconf import OmegaConf

        if options.current_config:
            log.stdout(f"{OmegaConf.to_yaml(config)}")
            sys.exit(0)

        log.info(f'Command: {" ".join(sys.argv)}')

        if options.agent_mode:
            from bbot.agent import Agent

            agent = Agent(config)
            success = agent.setup()
            if success:
                agent.start()

        else:
            from bbot.scanner import Scanner

            scanner = Scanner(
                *options.targets,
                modules=options.modules,
                output_modules=options.output_modules,
                config=config,
            )
            scanner.start()

    except bbot.core.errors.BBOTError as e:
        import traceback

        log.error(e)
        log.debug(traceback.format_exc())
        sys.exit(2)

    except Exception:
        import traceback

        log.error(f"Encountered unknown error: {traceback.format_exc()}")

    except KeyboardInterrupt:
        log.error("Interrupted")
        sys.exit(1)


if __name__ == "__main__":
    main()
