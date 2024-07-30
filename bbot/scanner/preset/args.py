import re
import logging
import argparse
from omegaconf import OmegaConf

from bbot.errors import *
from bbot.core.helpers.misc import chain_lists, get_closest_match, get_keys_in_dot_syntax

log = logging.getLogger("bbot.presets.args")


class BBOTArgs:

    # module config options to exclude from validation
    exclude_from_validation = re.compile(r".*modules\.[a-z0-9_]+\.(?:batch_size|module_threads)$")

    scan_examples = [
        (
            "Subdomains",
            "Perform a full subdomain enumeration on evilcorp.com",
            "bbot -t evilcorp.com -p subdomain-enum",
        ),
        (
            "Subdomains (passive only)",
            "Perform a passive-only subdomain enumeration on evilcorp.com",
            "bbot -t evilcorp.com -p subdomain-enum -rf passive",
        ),
        (
            "Subdomains + port scan + web screenshots",
            "Port-scan every subdomain, screenshot every webpage, output to current directory",
            "bbot -t evilcorp.com -p subdomain-enum -m portscan gowitness -n my_scan -o .",
        ),
        (
            "Subdomains + basic web scan",
            "A basic web scan includes wappalyzer, robots.txt, and other non-intrusive web modules",
            "bbot -t evilcorp.com -p subdomain-enum web-basic",
        ),
        (
            "Web spider",
            "Crawl www.evilcorp.com up to a max depth of 2, automatically extracting emails, secrets, etc.",
            "bbot -t www.evilcorp.com -p spider -c web.spider_distance=2 web.spider_depth=2",
        ),
        (
            "Everything everywhere all at once",
            "Subdomains, emails, cloud buckets, port scan, basic web, web screenshots, nuclei",
            "bbot -t evilcorp.com -p kitchen-sink",
        ),
    ]

    usage_examples = [
        (
            "List modules",
            "",
            "bbot -l",
        ),
        (
            "List presets",
            "",
            "bbot -lp",
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

        self.parser = self.create_parser()
        self._parsed = None

    @property
    def parsed(self):
        if self._parsed is None:
            self._parsed = self.parser.parse_args()
            self.sanitize_args()
        return self._parsed

    def preset_from_args(self):
        # the order here is important
        # first we make the preset
        args_preset = self.preset.__class__(
            *self.parsed.targets,
            whitelist=self.parsed.whitelist,
            blacklist=self.parsed.blacklist,
            strict_scope=self.parsed.strict_scope,
            name="args_preset",
        )

        # then we set verbosity levels (so if the user enables -d they can see debug output)
        if self.parsed.silent:
            args_preset.silent = True
        if self.parsed.verbose:
            args_preset.verbose = True
        if self.parsed.debug:
            args_preset.debug = True

        # then we load requested preset
        # this is important so we can load custom module directories, pull in custom flags, module config options, etc.
        for preset_arg in self.parsed.preset:
            try:
                args_preset.include_preset(preset_arg)
            except BBOTArgumentError:
                raise
            except Exception as e:
                raise BBOTArgumentError(f'Error parsing preset "{preset_arg}": {e}')

        # modules + flags
        args_preset.exclude_modules.update(set(self.parsed.exclude_modules))
        args_preset.exclude_flags.update(set(self.parsed.exclude_flags))
        args_preset.require_flags.update(set(self.parsed.require_flags))
        args_preset.explicit_scan_modules.update(set(self.parsed.modules))
        args_preset.explicit_output_modules.update(set(self.parsed.output_modules))
        args_preset.flags.update(set(self.parsed.flags))

        # output
        if self.parsed.json:
            args_preset.core.merge_custom({"modules": {"stdout": {"format": "json"}}})
        if self.parsed.brief:
            args_preset.core.merge_custom(
                {"modules": {"stdout": {"event_fields": ["type", "scope_description", "data"]}}}
            )
        if self.parsed.event_types:
            args_preset.core.merge_custom({"modules": {"stdout": {"event_types": self.parsed.event_types}}})

        # dependencies
        if self.parsed.retry_deps:
            args_preset.core.custom_config["deps_behavior"] = "retry_failed"
        elif self.parsed.force_deps:
            args_preset.core.custom_config["deps_behavior"] = "force_install"
        elif self.parsed.no_deps:
            args_preset.core.custom_config["deps_behavior"] = "disable"
        elif self.parsed.ignore_failed_deps:
            args_preset.core.custom_config["deps_behavior"] = "ignore_failed"

        # other scan options
        args_preset.scan_name = self.parsed.name
        args_preset.output_dir = self.parsed.output_dir
        args_preset.force_start = self.parsed.force

        if self.parsed.custom_headers:
            args_preset.core.merge_custom({"web": {"http_headers": self.parsed.custom_headers}})

        if self.parsed.custom_yara_rules:
            args_preset.core.merge_custom(
                {"modules": {"excavate": {"custom_yara_rules": self.parsed.custom_yara_rules}}}
            )

        # CLI config options (dot-syntax)
        for config_arg in self.parsed.config:
            try:
                # if that fails, try to parse as key=value syntax
                args_preset.core.merge_custom(OmegaConf.from_cli([config_arg]))
            except Exception as e:
                raise BBOTArgumentError(f'Error parsing command-line config option: "{config_arg}": {e}')

        return args_preset

    def create_parser(self, *args, **kwargs):
        kwargs.update(
            dict(
                description="Bighuge BLS OSINT Tool", formatter_class=argparse.RawTextHelpFormatter, epilog=self.epilog
            )
        )
        p = argparse.ArgumentParser(*args, **kwargs)

        target = p.add_argument_group(title="Target")
        target.add_argument(
            "-t", "--targets", nargs="+", default=[], help="Targets to seed the scan", metavar="TARGET"
        )
        target.add_argument(
            "-w",
            "--whitelist",
            nargs="+",
            default=None,
            help="What's considered in-scope (by default it's the same as --targets)",
        )
        target.add_argument("-b", "--blacklist", nargs="+", default=[], help="Don't touch these things")
        target.add_argument(
            "--strict-scope",
            action="store_true",
            help="Don't consider subdomains of target/whitelist to be in-scope",
        )
        presets = p.add_argument_group(title="Presets")
        presets.add_argument(
            "-p",
            "--preset",
            nargs="*",
            help="Enable BBOT preset(s)",
            metavar="PRESET",
            default=[],
        )
        presets.add_argument(
            "-c",
            "--config",
            nargs="*",
            help="Custom config options in key=value format: e.g. 'modules.shodan.api_key=1234'",
            metavar="CONFIG",
            default=[],
        )
        presets.add_argument("-lp", "--list-presets", action="store_true", help=f"List available presets.")

        modules = p.add_argument_group(title="Modules")
        modules.add_argument(
            "-m",
            "--modules",
            nargs="+",
            default=[],
            help=f'Modules to enable. Choices: {",".join(self.preset.module_loader.scan_module_choices)}',
            metavar="MODULE",
        )
        modules.add_argument("-l", "--list-modules", action="store_true", help=f"List available modules.")
        modules.add_argument(
            "-lmo", "--list-module-options", action="store_true", help="Show all module config options"
        )
        modules.add_argument(
            "-em", "--exclude-modules", nargs="+", default=[], help=f"Exclude these modules.", metavar="MODULE"
        )
        modules.add_argument(
            "-f",
            "--flags",
            nargs="+",
            default=[],
            help=f'Enable modules by flag. Choices: {",".join(self.preset.module_loader.flag_choices)}',
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
        modules.add_argument("--allow-deadly", action="store_true", help="Enable the use of highly aggressive modules")

        scan = p.add_argument_group(title="Scan")
        scan.add_argument("-n", "--name", help="Name of scan (default: random)", metavar="SCAN_NAME")
        scan.add_argument("-v", "--verbose", action="store_true", help="Be more verbose")
        scan.add_argument("-d", "--debug", action="store_true", help="Enable debugging")
        scan.add_argument("-s", "--silent", action="store_true", help="Be quiet")
        scan.add_argument(
            "--force",
            action="store_true",
            help="Run scan even in the case of condition violations or failed module setups",
        )
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

        output = p.add_argument_group(title="Output")
        output.add_argument(
            "-o",
            "--output-dir",
            help="Directory to output scan results",
            metavar="DIR",
        )
        output.add_argument(
            "-om",
            "--output-modules",
            nargs="+",
            default=[],
            help=f'Output module(s). Choices: {",".join(self.preset.module_loader.output_module_choices)}',
            metavar="MODULE",
        )
        output.add_argument("--json", "-j", action="store_true", help="Output scan data in JSON format")
        output.add_argument("--brief", "-br", action="store_true", help="Output only the data itself")
        output.add_argument("--event-types", nargs="+", default=[], help="Choose which event types to display")

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

        misc = p.add_argument_group(title="Misc")
        misc.add_argument("--version", action="store_true", help="show BBOT version and exit")
        misc.add_argument(
            "-H",
            "--custom-headers",
            nargs="+",
            default=[],
            help="List of custom headers as key value pairs (header=value).",
        )
        misc.add_argument("--custom-yara-rules", "-cy", help="Add custom yara rules to excavate")
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
        if self.parsed.whitelist is not None:
            self.parsed.whitelist = chain_lists(
                self.parsed.whitelist, try_files=True, msg="Reading whitelist from file: {filename}"
            )
        self.parsed.blacklist = chain_lists(
            self.parsed.blacklist, try_files=True, msg="Reading blacklist from file: {filename}"
        )
        self.parsed.flags = chain_lists(self.parsed.flags)
        self.parsed.exclude_flags = chain_lists(self.parsed.exclude_flags)
        self.parsed.require_flags = chain_lists(self.parsed.require_flags)
        self.parsed.event_types = [t.upper() for t in chain_lists(self.parsed.event_types)]

        # Custom Header Parsing / Validation
        custom_headers_dict = {}
        custom_header_example = "Example: --custom-headers foo=bar foo2=bar2"

        for i in self.parsed.custom_headers:
            parts = i.split("=", 1)
            if len(parts) != 2:
                raise ValidationError(f"Custom headers not formatted correctly (missing '='). {custom_header_example}")
            k, v = parts
            if not k or not v:
                raise ValidationError(
                    f"Custom headers not formatted correctly (missing header name or value). {custom_header_example}"
                )
            custom_headers_dict[k] = v
        self.parsed.custom_headers = custom_headers_dict

    def validate(self):
        # validate config options
        sentinel = object()
        all_options = set(get_keys_in_dot_syntax(self.preset.core.default_config))
        for c in self.parsed.config:
            c = c.split("=")[0].strip()
            v = OmegaConf.select(self.preset.core.default_config, c, default=sentinel)
            # if option isn't in the default config
            if v is sentinel:
                # skip if it's excluded from validation
                if self.exclude_from_validation.match(c):
                    continue
                # otherwise, ensure it exists as a module option
                raise ValidationError(get_closest_match(c, all_options, msg="config option"))
