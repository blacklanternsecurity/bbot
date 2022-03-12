#!/usr/bin/env python3

import sys
import logging
import argparse

# logging
from bbot.core.logger import init_logging
from bbot.modules import available_modules
logging_queue, logging_handlers = init_logging()

log = logging.getLogger('bbot.cli')


def main():

    parser = argparse.ArgumentParser(description='Bighuge BLS OSINT Tool')
    parser.add_argument('configuration', nargs='*', help='additional configuration options in key=value format')
    parser.add_argument(
        '-v', '--verbose', '--debug', action='store_true', help='Be more verbose'
    )
    parser.add_argument('-t', '--targets', nargs='+', default=[], help='Scan target')
    parser.add_argument('-m', '--modules', nargs='+', choices=list(available_modules), default=[], help='Modules')

    try:

        log.info(f'Command: {" ".join(sys.argv)}')
        options = parser.parse_args()

        # config test
        from . import config
        from omegaconf import OmegaConf
        log.info(f'Config:\n{OmegaConf.to_yaml(config)}')

        # scan test
        from bbot.scanner import Scanner
        scanner = Scanner('asdf', *options.targets, modules=options.modules, config=config)
        scanner.start()

    except argparse.ArgumentError as e:
        log.error(e)
        log.error('Check your syntax')
        sys.exit(2)

    except Exception as e:
        if options.verbose:
            import traceback

            log.error(traceback.format_exc())
        else:
            log.error(f'Encountered error (-v to debug): {e}')

    except KeyboardInterrupt:
        log.error('Interrupted')
        sys.exit(1)


if __name__ == '__main__':
    main()
