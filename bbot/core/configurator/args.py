import logging
import argparse
from omegaconf import OmegaConf
from contextlib import suppress
from bbot.modules import list_module_stems

from ..errors import ArgumentError

available_modules = list(list_module_stems())

log = logging.getLogger("bbot.core.configurator.args")


def chain_lists(l, try_files=False):
    """
    Chain together list, splitting entries on comma
    Optionally try to open entries as files and add their content to the list
    """
    final_list = dict()
    for entry in l:
        for s in entry.split(","):
            f = s.strip()
            if try_files:
                for line in str_or_file(f):
                    final_list[line.strip()] = None
            else:
                final_list[f] = None

    return list(final_list)


def str_or_file(s):
    try:
        with open(s, errors="ignore") as f:
            yield from f
    except OSError:
        yield s


class BBOTArgumentParser(argparse.ArgumentParser):
    _dummy = False

    def parse_args(self, *args, **kwargs):
        """
        Allow space or comma-separated entries for modules and targets
        For targets, also allow input files containing additional targets
        """
        ret = super().parse_args(*args, **kwargs)
        ret.modules = chain_lists(ret.modules)
        ret.targets = chain_lists(ret.targets, try_files=True)
        if "all" in ret.modules:
            ret.modules = available_modules
        else:
            for m in ret.modules:
                if not m in available_modules and not self._dummy:
                    raise ArgumentError(
                        f'Module "{m}" is not valid. Choose from: {",".join(available_modules)}'
                    )
        return ret


class DummyArgumentParser(BBOTArgumentParser):
    _dummy = True

    def error(self, message):
        pass


parser = BBOTArgumentParser(description="Bighuge BLS OSINT Tool")
dummy_parser = DummyArgumentParser(description="Bighuge BLS OSINT Tool")
for p in (parser, dummy_parser):
    p.add_argument("-t", "--targets", nargs="+", default=[], help="Scan target")
    p.add_argument(
        "-m",
        "--modules",
        nargs="+",
        default=[],
        help=f'Modules (specify keyword "all" to enable all modules). Choices: {",".join(available_modules)}',
    )
    p.add_argument(
        "-c",
        "--configuration",
        nargs="*",
        help="additional configuration options in key=value format",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Be more verbose")
    p.add_argument("-d", "--debug", action="store_true", help="Enable debugging")
    p.add_argument(
        "--current-config",
        action="store_true",
        help="Show current config in YAML format",
    )


cli_options = None
with suppress(Exception):
    cli_options = dummy_parser.parse_args()


def get_config():
    cli_config = []
    with suppress(Exception):
        if cli_options.configuration:
            cli_config = cli_options.configuration
    with suppress(Exception):
        return OmegaConf.from_cli(cli_config)
    return OmegaConf.create()
