import re
import sys
import logging
import argparse
from pathlib import Path
from omegaconf import OmegaConf

from bbot.core.helpers.logger import log_to_stderr
from bbot.core.helpers.misc import chain_lists, match_and_exit, is_file

log = logging.getLogger("bbot.presets.args")


class BBOTArgs:

    # module config options to exclude from validation
    exclude_from_validation = re.compile(r".*modules\.[a-z0-9_]+\.(?:batch_size|max_event_handlers)$")

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

    def __init__(self, preset):
        self.preset = preset
        self._config = None

        # validate module choices
        self._module_choices = sorted(set(self.preset.module_loader.preloaded(type="scan")))
        self._output_module_choices = sorted(set(self.preset.module_loader.preloaded(type="output")))
        self._flag_choices = set()
        for m, c in self.preset.module_loader.preloaded().items():
            self._flag_choices.update(set(c.get("flags", [])))
        self._flag_choices = sorted(self._flag_choices)

        self.parser = self.create_parser()
        self._parsed = None

    @property
    def parsed(self):
        if self._parsed is None:
            self._parsed = self.parser.parse_args()
            self.sanitize_args()
        return self._parsed

    def preset_from_args(self):
        args_preset = self.preset.__class__(
            *self.parsed.targets,
            whitelist=self.parsed.whitelist,
            blacklist=self.parsed.blacklist,
            strict_scope=self.parsed.strict_scope,
        )

        # modules && flags (excluded then required then all others)
        args_preset.exclude_modules = self.parsed.exclude_modules
        args_preset.exclude_flags = self.parsed.exclude_flags
        args_preset.require_flags = self.parsed.require_flags
        args_preset.modules = self.parsed.modules

        for output_module in self.parsed.output_modules:
            args_preset.add_module(output_module, module_type="output")

        args_preset.flags = self.parsed.flags

        # additional custom presets / config options
        for preset_param in self.parsed.preset:
            if Path(preset_param).is_file():
                try:
                    custom_preset = self.preset.from_yaml_file(preset_param)
                except Exception as e:
                    log_to_stderr(f"Error parsing custom config at {preset_param}: {e}", level="ERROR")
                    sys.exit(2)
                args_preset.merge(custom_preset)
            else:
                try:
                    cli_config = OmegaConf.from_cli([preset_param])
                except Exception as e:
                    log_to_stderr(f"Error parsing command-line config: {e}", level="ERROR")
                    sys.exit(2)
                args_preset.core.merge_custom(cli_config)

        # verbosity levels
        if self.parsed.silent:
            args_preset.silent = True
        if self.parsed.verbose:
            args_preset.verbose = True
        if self.parsed.debug:
            args_preset.debug = True

        # dependencies
        if self.parsed.retry_deps:
            args_preset.core.custom_config["deps_behavior"] = "retry_failed"
        elif self.parsed.force_deps:
            args_preset.core.custom_config["deps_behavior"] = "force_install"
        elif self.parsed.no_deps:
            args_preset.core.custom_config["deps_behavior"] = "disable"
        elif self.parsed.ignore_failed_deps:
            args_preset.core.custom_config["deps_behavior"] = "ignore_failed"

        return args_preset

    def create_parser(self, *args, **kwargs):
        kwargs.update(
            dict(
                description="Bighuge BLS OSINT Tool", formatter_class=argparse.RawTextHelpFormatter, epilog=self.epilog
            )
        )
        p = argparse.ArgumentParser(*args, **kwargs)
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
            help=f'Modules to enable. Choices: {",".join(self._module_choices)}',
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
            help=f'Enable modules by flag. Choices: {",".join(self._flag_choices)}',
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
            default=[],
            help=f'Output module(s). Choices: {",".join(self._output_module_choices)}',
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
            "-p",
            "--preset",
            "-c",
            "--config",
            nargs="*",
            help="Custom preset file(s), or config options in key=value format: 'modules.shodan.api_key=1234'",
            metavar="CONFIG",
            default=[],
        )
        scan.add_argument("-v", "--verbose", action="store_true", help="Be more verbose")
        scan.add_argument("-d", "--debug", action="store_true", help="Enable debugging")
        scan.add_argument("-s", "--silent", action="store_true", help="Be quiet")
        scan.add_argument("--force", action="store_true", help="Run scan even if module setups fail")
        scan.add_argument("-y", "--yes", action="store_true", help="Skip scan confirmation prompt")
        scan.add_argument("--dry-run", action="store_true", help=f"Abort before executing scan")
        scan.add_argument(
            "--current-preset",
            action="store_true",
            help="Show the current preset in YAML format",
        )
        scan.add_argument(
            "--current-preset-full",
            action="store_true",
            help="Show the current preset in its full form, including defaults",
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

    def sanitize_args(self):
        # silent implies -y
        if self.parsed.silent:
            self.parsed.yes = True
        # chain_lists allows either comma-separated or space-separated lists
        self.parsed.modules = chain_lists(self.parsed.modules)
        self.parsed.exclude_modules = chain_lists(self.parsed.exclude_modules)
        self.parsed.output_modules = chain_lists(self.parsed.output_modules)
        self.parsed.targets = chain_lists(
            self.parsed.targets, try_files=True, msg="Reading targets from file: {filename}"
        )
        self.parsed.whitelist = chain_lists(
            self.parsed.whitelist, try_files=True, msg="Reading whitelist from file: {filename}"
        )
        self.parsed.blacklist = chain_lists(
            self.parsed.blacklist, try_files=True, msg="Reading blacklist from file: {filename}"
        )
        self.parsed.flags = chain_lists(self.parsed.flags)
        self.parsed.exclude_flags = chain_lists(self.parsed.exclude_flags)
        self.parsed.require_flags = chain_lists(self.parsed.require_flags)

    def validate(self):
        # validate config options
        sentinel = object()
        conf = [a for a in self.parsed.preset if not is_file(a)]
        all_options = None
        for c in conf:
            c = c.split("=")[0].strip()
            v = OmegaConf.select(self.preset.core.default_config, c, default=sentinel)
            # if option isn't in the default config
            if v is sentinel:
                # skip if it's excluded from validation
                if self.exclude_from_validation.match(c):
                    continue
                if all_options is None:
                    modules_options = set()
                    for module_options in self.preset.module_loader.modules_options().values():
                        modules_options.update(set(o[0] for o in module_options))
                    global_options = set(self.preset.core.default_config.keys()) - {"modules"}
                    all_options = global_options.union(modules_options)
                # otherwise, ensure it exists as a module option
                match_and_exit(c, all_options, msg="module option")

        # validate modules
        for m in self.parsed.modules:
            if m not in self._module_choices:
                match_and_exit(m, self._module_choices, msg="module")
        for m in self.parsed.exclude_modules:
            if m not in self._module_choices:
                match_and_exit(m, self._module_choices, msg="module")
        for m in self.parsed.output_modules:
            if m not in self._output_module_choices:
                match_and_exit(m, self._output_module_choices, msg="output module")

        # validate flags
        for f in set(self.parsed.flags + self.parsed.require_flags + self.parsed.exclude_flags):
            if f not in self._flag_choices:
                match_and_exit(f, self._flag_choices, msg="flag")
