import logging
import argparse
from pathlib import Path
from datetime import datetime
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
        ret.targets = chain_lists(ret.targets, try_files=True, msg="Reading targets from file: {filename}")
        ret.flags = chain_lists(ret.flags)
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
        # -oA
        if ret.output_all:
            for om_modname in ("human", "csv", "json"):
                if om_modname not in ret.output_modules:
                    ret.output_modules.append(om_modname)
            output_path = Path(ret.output_all).resolve()
            if output_path.is_dir():
                date = datetime.now().isoformat().replace(":", "_")
                ret.output_all = output_path / f"bbot_{date}"
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
        help=f'Modules to enable. Choices: {",".join(list(modules_preloaded))}',
    )
    p.add_argument(
        "-f",
        "--flags",
        nargs="+",
        default=[],
        help=f'Enable modules by flag. Choices: {",".join(list(flag_choices))}',
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
        "-oA",
        "--output-all",
        help=f"Output in CSV, JSON, and TXT at this file location",
        metavar="BASE_FILENAME",
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
    wordcloud = p.add_argument_group(
        title="Word cloud", description="Save/load wordlist of common words gathered during a scan"
    )
    g1 = wordcloud.add_mutually_exclusive_group()
    wordcloud.add_argument("--save-wordcloud", help="Output wordcloud to file when the scan completes", metavar="FILE")
    g1.add_argument("--load-wordcloud", help="Load wordcloud from a file and use it in the scan", metavar="FILE")
    g1.add_argument(
        "--load-last-wordcloud", action="store_true", help="Load the wordcloud from the last scan (from $BBOT_HOME)"
    )
    deps = p.add_argument_group(
        title="Module dependencies", description="Control how modules install their dependencies"
    )
    g2 = deps.add_mutually_exclusive_group()
    deps.add_argument(
        "--ignore-failed-deps", action="store_true", help="Run modules even if their dependency setup failed"
    )
    g2.add_argument("--no-deps", action="store_true", help="Don't install module dependencies")
    g2.add_argument("--force-deps", action="store_true", help="Force install all module dependencies")
    g2.add_argument("--retry-deps", action="store_true", help="Retry failed module dependencies")
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
