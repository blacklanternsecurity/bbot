import logging
import argparse
from omegaconf import OmegaConf
from contextlib import suppress

from ...modules import output
from ..errors import ArgumentError
from ...modules import module_stems
from ..helpers.misc import chain_lists

log = logging.getLogger("bbot.core.configurator.args")


class BBOTArgumentParser(argparse.ArgumentParser):
    _dummy = False

    def parse_args(self, *args, **kwargs):
        """
        Allow space or comma-separated entries for modules and targets
        For targets, also allow input files containing additional targets
        """
        ret = super().parse_args(*args, **kwargs)
        ret.modules = chain_lists(ret.modules)
        ret.output_modules = chain_lists(ret.output_modules)
        ret.targets = chain_lists(ret.targets, try_files=True)
        if "all" in ret.modules:
            ret.modules = module_stems
        else:
            for m in ret.modules:
                if not m in module_stems and not self._dummy:
                    raise ArgumentError(
                        f'Module "{m}" is not valid. Choose from: {",".join(module_stems)}'
                    )
        for m in ret.output_modules:
            if not m in output.module_stems and not self._dummy:
                raise ArgumentError(
                    f'Output module "{m}" is not valid. Choose from: {",".join(output.module_stems)}'
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
        help=f'Modules (specify keyword "all" to enable all modules). Choices: {",".join(module_stems)}',
    )
    p.add_argument(
        "-o",
        "--output-modules",
        nargs="+",
        default=["human"],
        help=f'Output module(s). Choices: {",".join(output.module_stems)}',
        metavar="MODULES",
    )
    p.add_argument(
        "-a",
        "--agent-mode",
        action="store_true"
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
