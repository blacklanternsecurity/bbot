import sys
import argparse
from pathlib import Path
from omegaconf import OmegaConf
from contextlib import suppress

from ..helpers.logger import log_to_stderr
from ..helpers.misc import chain_lists, match_and_exit, is_file


class BBOTArgumentParser(argparse.ArgumentParser):
    """
    A subclass of argparse.ArgumentParser with several extra features:
        - permissive parsing of modules/flags, allowing either space or comma-separated entries
        - loading targets / config from files
        - option to *not* exit on error
    """

    def __init__(self, *args, **kwargs):
        self._dummy = kwargs.pop("_dummy", False)
        self.bbot_core = kwargs.pop("_core")
        self._module_choices = sorted(set(self.bbot_core.module_loader.configs(type="scan")))
        self._output_module_choices = sorted(set(self.bbot_core.module_loader.configs(type="output")))
        self._flag_choices = set()
        for m, c in self.bbot_core.module_loader.preloaded().items():
            self._flag_choices.update(set(c.get("flags", [])))
        super().__init__(*args, **kwargs)

    def error(self, message):
        if not self._dummy:
            return super().error(message)

    def parse_args(self, *args, **kwargs):
        """
        Allow space or comma-separated entries for modules and targets
        For targets, also allow input files containing additional targets
        """
        ret = super().parse_args(*args, **kwargs)
        # silent implies -y
        if ret.silent:
            ret.yes = True
        ret.modules = chain_lists(ret.modules)
        ret.exclude_modules = chain_lists(ret.exclude_modules)
        ret.output_modules = chain_lists(ret.output_modules)
        ret.targets = chain_lists(ret.targets, try_files=True, msg="Reading targets from file: {filename}")
        ret.whitelist = chain_lists(ret.whitelist, try_files=True, msg="Reading whitelist from file: {filename}")
        ret.blacklist = chain_lists(ret.blacklist, try_files=True, msg="Reading blacklist from file: {filename}")
        ret.flags = chain_lists(ret.flags)
        ret.exclude_flags = chain_lists(ret.exclude_flags)
        ret.require_flags = chain_lists(ret.require_flags)
        if not self._dummy:
            for m in ret.modules:
                if m not in self._module_choices:
                    match_and_exit(m, self._module_choices, msg="module")
            for m in ret.exclude_modules:
                if m not in self._module_choices:
                    match_and_exit(m, self._module_choices, msg="module")
            for m in ret.output_modules:
                if m not in self._output_module_choices:
                    match_and_exit(m, self._output_module_choices, msg="output module")
            for f in set(ret.flags + ret.require_flags):
                if f not in self._flag_choices:
                    match_and_exit(f, self._flag_choices, msg="flag")
        return ret


class BBOTArgs:
    scan_examples = [
        (
            "Subdomains",
            "Perform a full subdomain enumeration on evilcorp.com",
            "bbot -t evilcorp.com -f subdomain-enum",
        ),
        (
            "Subdomains (passive only)",
            "Perform a passive-only subdomain enumeration on evilcorp.com",
            "bbot -t evilcorp.com -f subdomain-enum -rf passive",
        ),
        (
            "Subdomains + port scan + web screenshots",
            "Port-scan every subdomain, screenshot every webpage, output to current directory",
            "bbot -t evilcorp.com -f subdomain-enum -m nmap gowitness -n my_scan -o .",
        ),
        (
            "Subdomains + basic web scan",
            "A basic web scan includes wappalyzer, robots.txt, and other non-intrusive web modules",
            "bbot -t evilcorp.com -f subdomain-enum web-basic",
        ),
        (
            "Web spider",
            "Crawl www.evilcorp.com up to a max depth of 2, automatically extracting emails, secrets, etc.",
            "bbot -t www.evilcorp.com -m httpx robots badsecrets secretsdb -c web_spider_distance=2 web_spider_depth=2",
        ),
        (
            "Everything everywhere all at once",
            "Subdomains, emails, cloud buckets, port scan, basic web, web screenshots, nuclei",
            "bbot -t evilcorp.com -f subdomain-enum email-enum cloud-enum web-basic -m nmap gowitness nuclei --allow-deadly",
        ),
    ]

    usage_examples = [
        (
            "List modules",
            "",
            "bbot -l",
        ),
        (
            "List flags",
            "",
            "bbot -lf",
        ),
    ]

    epilog = "EXAMPLES\n"
    for example in (scan_examples, usage_examples):
        for title, description, command in example:
            epilog += f"\n    {title}:\n        {command}\n"

    def __init__(self, core):
        self.core = core
        self.parser = self.create_parser(_core=self.core)
        self.dummy_parser = self.create_parser(_core=self.core, _dummy=True)
        self._parsed = None
        self._cli_config = None

    @property
    def parsed(self):
        """
        Returns the parsed BBOT Argument Parser.
        """
        if self._parsed is None:
            self._parsed = self.dummy_parser.parse_args()
        return self._parsed

    @property
    def cli_config(self):
        if self._cli_config is None:
            with suppress(Exception):
                if self.parsed.config:
                    cli_config = self.parsed.config
                    if cli_config:
                        filename = Path(cli_config[0]).resolve()
                        if len(cli_config) == 1 and is_file(filename):
                            try:
                                conf = OmegaConf.load(str(filename))
                                log_to_stderr(f"Loaded custom config from {filename}")
                                return conf
                            except Exception as e:
                                log_to_stderr(f"Error parsing custom config at {filename}: {e}", level="ERROR")
                                sys.exit(2)
                    try:
                        self._cli_config = OmegaConf.from_cli(cli_config)
                    except Exception as e:
                        log_to_stderr(f"Error parsing command-line config: {e}", level="ERROR")
                        sys.exit(2)
        if self._cli_config is None:
            self._cli_config = OmegaConf.create({})
        return self._cli_config

    def create_parser(self, *args, **kwargs):
        kwargs.update(
            dict(
                description="Bighuge BLS OSINT Tool", formatter_class=argparse.RawTextHelpFormatter, epilog=self.epilog
            )
        )
        p = BBOTArgumentParser(*args, **kwargs)
        p.add_argument("--help-all", action="store_true", help="Display full help including module config options")
        target = p.add_argument_group(title="Target")
        target.add_argument(
            "-t", "--targets", nargs="+", default=[], help="Targets to seed the scan", metavar="TARGET"
        )
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
        modules = p.add_argument_group(title="Modules")
        modules.add_argument(
            "-m",
            "--modules",
            nargs="+",
            default=[],
            help=f'Modules to enable. Choices: {",".join(p._module_choices)}',
            metavar="MODULE",
        )
        modules.add_argument("-l", "--list-modules", action="store_true", help=f"List available modules.")
        modules.add_argument(
            "-em", "--exclude-modules", nargs="+", default=[], help=f"Exclude these modules.", metavar="MODULE"
        )
        modules.add_argument(
            "-f",
            "--flags",
            nargs="+",
            default=[],
            help=f'Enable modules by flag. Choices: {",".join(sorted(p._flag_choices))}',
            metavar="FLAG",
        )
        modules.add_argument("-lf", "--list-flags", action="store_true", help=f"List available flags.")
        modules.add_argument(
            "-rf",
            "--require-flags",
            nargs="+",
            default=[],
            help=f"Only enable modules with these flags (e.g. -rf passive)",
            metavar="FLAG",
        )
        modules.add_argument(
            "-ef",
            "--exclude-flags",
            nargs="+",
            default=[],
            help=f"Disable modules with these flags. (e.g. -ef aggressive)",
            metavar="FLAG",
        )
        modules.add_argument(
            "-om",
            "--output-modules",
            nargs="+",
            default=["human", "json", "csv"],
            help=f'Output module(s). Choices: {",".join(p._output_module_choices)}',
            metavar="MODULE",
        )
        modules.add_argument("--allow-deadly", action="store_true", help="Enable the use of highly aggressive modules")
        scan = p.add_argument_group(title="Scan")
        scan.add_argument("-n", "--name", help="Name of scan (default: random)", metavar="SCAN_NAME")
        scan.add_argument(
            "-o",
            "--output-dir",
            metavar="DIR",
        )
        scan.add_argument(
            "-c",
            "--config",
            nargs="*",
            help="custom config file, or configuration options in key=value format: 'modules.shodan.api_key=1234'",
            metavar="CONFIG",
        )
        scan.add_argument("-v", "--verbose", action="store_true", help="Be more verbose")
        scan.add_argument("-d", "--debug", action="store_true", help="Enable debugging")
        scan.add_argument("-s", "--silent", action="store_true", help="Be quiet")
        scan.add_argument("--force", action="store_true", help="Run scan even if module setups fail")
        scan.add_argument("-y", "--yes", action="store_true", help="Skip scan confirmation prompt")
        scan.add_argument("--dry-run", action="store_true", help=f"Abort before executing scan")
        scan.add_argument(
            "--current-config",
            action="store_true",
            help="Show current config in YAML format",
        )
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
        return p
