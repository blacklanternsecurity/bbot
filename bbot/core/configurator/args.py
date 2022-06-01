import logging
import argparse
from omegaconf import OmegaConf
from contextlib import suppress

from ...modules import output
from ..errors import ArgumentError
from ..helpers.misc import chain_lists
from ...modules import modules_preloaded

log = logging.getLogger("bbot.core.configurator.args")

flag_choices = set()
for m, c in modules_preloaded.items():
    flag_choices.update(set(c.get("flags", [])))


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
        ret.flags = chain_lists(ret.flags)
        if "all" in ret.modules:
            ret.modules = list(modules_preloaded)
        else:
            for m in ret.modules:
                if m not in modules_preloaded and not self._dummy:
                    raise ArgumentError(f'Module "{m}" is not valid. Choose from: {",".join(list(modules_preloaded))}')
        for m in ret.output_modules:
            if m not in output.modules_preloaded and not self._dummy:
                raise ArgumentError(
                    f'Output module "{m}" is not valid. Choose from: {",".join(list(output.modules_preloaded))}'
                )
        for f in ret.flags:
            if f not in flag_choices and not self._dummy:
                raise ArgumentError(f'Flag "{f}" is not valid. Choose from: {",".join(list(flag_choices))}')
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
        help=f'Modules ("all" to enable all modules). Choices: {",".join(list(modules_preloaded))}',
    )
    p.add_argument(
        "-f",
        "--flags",
        nargs="+",
        default=[],
        help=f'Select modules by flag. Choices: {",".join(list(flag_choices))}',
    )
    p.add_argument(
        "-o",
        "--output-modules",
        nargs="+",
        default=["human"],
        help=f'Output module(s). Choices: {",".join(list(output.modules_preloaded))}',
        metavar="MODULES",
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
    deps = p.add_argument_group(
        title="Module dependencies", description="Control how modules install their dependencies"
    )
    g = deps.add_mutually_exclusive_group()
    deps.add_argument(
        "--ignore-failed-deps", action="store_true", help="Run modules even if their dependency setup failed"
    )
    g.add_argument("--no-deps", action="store_true", help="Don't install module dependencies")
    g.add_argument("--force-deps", action="store_true", help="Force install all module dependencies")
    g.add_argument("--retry-deps", action="store_true", help="Retry failed module dependencies")
    agent = p.add_argument_group(title="Agent", description="Report back to a central server")
    agent.add_argument("-a", "--agent-mode", action="store_true", help="Start in agent mode")


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
