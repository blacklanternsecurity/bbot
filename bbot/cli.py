#!/usr/bin/env python3

import os
import sys
import logging
from omegaconf import OmegaConf
from contextlib import suppress

# fix tee buffering
sys.stdout.reconfigure(line_buffering=True)

# logging
from bbot.core.logger import init_logging

logging_queue, logging_handlers = init_logging()

import bbot.core.errors
from bbot.modules import module_loader
from bbot.core.configurator.args import parser
from bbot.core.configurator.files import config_filename

log = logging.getLogger("bbot.cli")
sys.stdout.reconfigure(line_buffering=True)


def main():

    try:
        # ensure bbot.conf
        from . import config

        if not config_filename.exists():
            log.hugeinfo(f"Creating bbot.conf at {config_filename}")
            OmegaConf.save(config=config, f=str(config_filename))

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

        # --current-config
        if options.current_config:
            log.stdout(f"{OmegaConf.to_yaml(config)}")
            sys.exit(0)

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

                # enable modules by dependency
                all_modules = list(set(scanner._scan_modules + scanner._internal_modules + scanner._output_modules))
                while 1:
                    changed = False
                    dep_choices = module_loader.recommend_dependencies(all_modules)
                    if not dep_choices:
                        break
                    for event_type, deps in dep_choices.items():
                        # skip resolving dependency if a target provides the missing type
                        if any(e.type == event_type for e in scanner.target.events):
                            continue
                        required_by = deps["required_by"]
                        recommended = deps["recommended"]
                        if not recommended:
                            log.warning(
                                f"{len(required_by):,} modules ({','.join(required_by)}) rely on {event_type} but no modules produce it"
                            )
                        elif len(recommended) == 1:
                            log.warning(
                                f"Enabling {next(iter(recommended))} because {len(required_by):,} modules ({','.join(required_by)}) rely on it for {event_type}"
                            )
                            all_modules = list(set(all_modules + list(recommended)))
                            scanner._scan_modules = list(set(scanner._scan_modules + list(recommended)))
                            changed = True
                        else:
                            log.warning(
                                f"{len(required_by):,} modules ({','.join(required_by)}) rely on {event_type} but no modules produce it"
                            )
                            log.warning(
                                f"Recommend enabling one or more of the following modules which produce {event_type}:"
                            )
                            for m in recommended:
                                log.warning(f" - {m}")
                    if not changed:
                        break

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
