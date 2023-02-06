import sys
import argparse
from pathlib import Path
from omegaconf import OmegaConf
from contextlib import suppress

from ..errors import ArgumentError
from ...modules import module_loader
from ..helpers.misc import chain_lists
from ..helpers.logger import log_to_stderr

module_choices = sorted(set(module_loader.configs(type="scan")))
output_module_choices = sorted(set(module_loader.configs(type="output")))

flag_choices = set()
for m, c in module_loader.preloaded().items():
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
        ret.whitelist = chain_lists(ret.whitelist, try_files=True, msg="Reading whitelist from file: {filename}")
        ret.blacklist = chain_lists(ret.blacklist, try_files=True, msg="Reading blacklist from file: {filename}")
        ret.flags = chain_lists(ret.flags)
        ret.require_flags = chain_lists(ret.require_flags)
        for m in ret.modules:
            if m not in module_choices and not self._dummy:
                raise ArgumentError(f'Module "{m}" is not valid. Choose from: {",".join(module_choices)}')
        for m in ret.exclude_modules:
            if m not in module_choices and not self._dummy:
                raise ArgumentError(f'Cannot exclude module "{m}". Choose from: {",".join(module_choices)}')
        for m in ret.output_modules:
            if m not in output_module_choices and not self._dummy:
                raise ArgumentError(
                    f'Output module "{m}" is not valid. Choose from: {",".join(output_module_choices)}'
                )
        for f in set(ret.flags + ret.require_flags):
            if f not in flag_choices and not self._dummy:
                raise ArgumentError(f'Flag "{f}" is not valid. Choose from: {",".join(sorted(flag_choices))}')
        return ret


class DummyArgumentParser(BBOTArgumentParser):
    _dummy = True

    def error(self, message):
        pass


epilog = """EXAMPLES

    list modules:
        bbot -l

    subdomain enumeration:
        bbot -t evilcorp.com -f subdomain-enum -m httpx

    passive modules only:
        bbot -t evilcorp.com -f passive

    subdomains + web screenshots:
        bbot -t targets.txt -f subdomain-enum -m httpx gowitness --name my_scan --output-dir .

    subdomains + basic web scanning:
        bbot -t evilcorp.com -f subdomain-enum web-basic

    single module:
        bbot -t evilcorp.com -m github -c modules.github.api_key=deadbeef

    web spider + advanced web scan:
        bbot -t www.evilcorp.com -m httpx -f web-basic web-advanced -c web_spider_distance=2 web_spider_depth=2

    subdomains + emails + cloud buckets + portscan + screenshots + nuclei:
        bbot -t evilcorp.com -f subdomain-enum email-enum cloud-enum web-basic -m naabu gowitness nuclei --allow-deadly

"""


parser = BBOTArgumentParser(
    description="Bighuge BLS OSINT Tool", formatter_class=argparse.RawTextHelpFormatter, epilog=epilog
)
dummy_parser = DummyArgumentParser(
    description="Bighuge BLS OSINT Tool", formatter_class=argparse.RawTextHelpFormatter, epilog=epilog
)
for p in (parser, dummy_parser):
    p.add_argument("--help-all", action="store_true", help="Display full help including module config options")
    target = p.add_argument_group(title="Target")
    target.add_argument("-t", "--targets", nargs="+", default=[], help="Targets to seed the scan", metavar="TARGET")
    target.add_argument(
        "-w",
        "--whitelist",
        nargs="+",
        default=[],
        help="What's considered in-scope (by default it's the same as --targets)",
    )
    target.add_argument("-b", "--blacklist", nargs="+", default=[], help="Don't touch these things")
    target.add_argument(
        "--strict-scope",
        action="store_true",
        help="Don't consider subdomains of target/whitelist to be in-scope",
    )
    p.add_argument("-n", "--name", help="Name of scan (default: random)", metavar="SCAN_NAME")
    p.add_argument(
        "-m",
        "--modules",
        nargs="+",
        default=[],
        help=f'Modules to enable. Choices: {",".join(module_choices)}',
        metavar="MODULE",
    )
    p.add_argument("-l", "--list-modules", action="store_true", help=f"List available modules.")
    p.add_argument("-em", "--exclude-modules", nargs="+", default=[], help=f"Exclude these modules.", metavar="MODULE")
    p.add_argument(
        "-f",
        "--flags",
        nargs="+",
        default=[],
        help=f'Enable modules by flag. Choices: {",".join(sorted(flag_choices))}',
        metavar="FLAG",
    )
    p.add_argument(
        "-rf",
        "--require-flags",
        nargs="+",
        default=[],
        help=f"Disable modules that don't have these flags (e.g. --require-flags passive)",
        metavar="FLAG",
    )
    p.add_argument(
        "-ef",
        "--exclude-flags",
        nargs="+",
        default=[],
        help=f"Disable modules with these flags. (e.g. --exclude-flags brute-force)",
        metavar="FLAG",
    )
    p.add_argument(
        "-om",
        "--output-modules",
        nargs="+",
        default=["human", "json", "csv"],
        help=f'Output module(s). Choices: {",".join(output_module_choices)}',
        metavar="MODULE",
    )
    p.add_argument(
        "-o",
        "--output-dir",
        metavar="DIR",
    )
    p.add_argument(
        "-c",
        "--config",
        nargs="*",
        help="custom config file, or configuration options in key=value format: 'modules.shodan.api_key=1234'",
        metavar="CONFIG",
    )
    p.add_argument("--allow-deadly", action="store_true", help="Enable the use of highly aggressive modules")
    p.add_argument("-v", "--verbose", action="store_true", help="Be more verbose")
    p.add_argument("-d", "--debug", action="store_true", help="Enable debugging")
    p.add_argument("-s", "--silent", action="store_true", help="Be quiet")
    p.add_argument("--force", action="store_true", help="Run scan even if module setups fail")
    p.add_argument("-y", "--yes", action="store_true", help="Skip scan confirmation prompt")
    p.add_argument("--dry-run", action="store_true", help=f"Abort before executing scan")
    p.add_argument(
        "--current-config",
        action="store_true",
        help="Show current config in YAML format",
    )
    wordcloud = p.add_argument_group(
        title="Word cloud", description="Save/load wordlist of common words gathered during a scan"
    )
    wordcloud.add_argument(
        "--save-wordcloud", help="Output wordcloud to custom file when the scan completes", metavar="FILE"
    )
    wordcloud.add_argument("--load-wordcloud", help="Load wordcloud from a custom file", metavar="FILE")
    deps = p.add_argument_group(
        title="Module dependencies", description="Control how modules install their dependencies"
    )
    g2 = deps.add_mutually_exclusive_group()
    g2.add_argument("--no-deps", action="store_true", help="Don't install module dependencies")
    g2.add_argument("--force-deps", action="store_true", help="Force install all module dependencies")
    g2.add_argument("--retry-deps", action="store_true", help="Try again to install failed module dependencies")
    g2.add_argument(
        "--ignore-failed-deps", action="store_true", help="Run modules even if they have failed dependencies"
    )
    g2.add_argument("--install-all-deps", action="store_true", help="Install dependencies for all modules")
    agent = p.add_argument_group(title="Agent", description="Report back to a central server")
    agent.add_argument("-a", "--agent-mode", action="store_true", help="Start in agent mode")
    misc = p.add_argument_group(title="Misc")
    misc.add_argument("--version", action="store_true", help="show BBOT version and exit")


cli_options = None
with suppress(Exception):
    cli_options = dummy_parser.parse_args()


def get_config():
    cli_config = []
    with suppress(Exception):
        if cli_options.config:
            cli_config = cli_options.config
    if len(cli_config) == 1:
        filename = Path(cli_config[0]).resolve()
        if filename.is_file():
            try:
                conf = OmegaConf.load(str(filename))
                log_to_stderr(f"Loaded custom config from {filename}")
                return conf
            except Exception as e:
                log_to_stderr(f"Error parsing custom config at {filename}: {e}", level="ERROR")
                sys.exit(2)
    try:
        return OmegaConf.from_cli(cli_config)
    except Exception as e:
        log_to_stderr(f"Error parsing command-line config: {e}", level="ERROR")
        sys.exit(2)
