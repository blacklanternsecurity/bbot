#!/usr/bin/env python3

import os
import sys
import logging
from contextlib import suppress

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
        try:
            options = parser.parse_args()
        except bbot.core.errors.ArgumentError as e:
            log.warning(e)
            sys.exit(1)
            # this is intentional since sys.exit() is monkeypatched in the tests
            return

        # config test
        from . import config
        from omegaconf import OmegaConf

        if options.current_config:
            log.stdout(f"{OmegaConf.to_yaml(config)}")
            sys.exit(0)

        # don't debug to file if debug isn't enabled
        if not config.get("debug", False):
            logging_handlers["file_debug"].filters = [lambda x: False]

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
                scanner = Scanner(
                    *options.targets,
                    modules=options.modules,
                    module_flags=options.flags,
                    output_modules=options.output_modules,
                    config=config,
                    whitelist=options.whitelist,
                    blacklist=options.blacklist,
                )
                if options.load_wordcloud:
                    scanner.helpers.word_cloud.load(options.load_wordcloud)
                elif options.load_last_wordcloud:
                    scanner.helpers.word_cloud.load()
                scanner.start()
            except Exception:
                raise
            finally:
                with suppress(NameError):
                    scanner.helpers.word_cloud.save(options.save_wordcloud)

    except bbot.core.errors.BBOTError as e:
        import traceback

        log.error(e)
        log.debug(traceback.format_exc())
        sys.exit(2)

    except Exception:
        import traceback

        log.error(f"Encountered unknown error: {traceback.format_exc()}")

    except KeyboardInterrupt:
        handler = logging_handlers["stderr"]
        record = logging.LogRecord(
            name="bbot.cli", msg="Interrupted", level=logging.ERROR, pathname=None, lineno=0, args=None, exc_info=None
        )
        print(handler.formatter.format(record))
        os._exit(1)


if __name__ == "__main__":
    main()
