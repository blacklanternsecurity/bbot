import os
import logging
import argparse

from bbot.errors import *
from bbot.core.config.merge import dotted_set
from bbot.core.config.models import coerce_value
from bbot.core.helpers.misc import chain_lists


def _parse_cli_value(raw: str, adapter=None):
    """Parse the RHS of a `-c a.b.c=value` argument.

    `adapter` is the target field's pydantic TypeAdapter (from the config type
    index), or None when the field is unknown. Coercion follows the declared type:
    string fields keep the literal text (lossless), bool fields produce a real bool,
    int/float fields parse via YAML, and unknown fields fall back to plain YAML
    coercion.
    """
    if raw == "":
        return ""
    return coerce_value(raw, adapter)


def parse_dotted_cli(entries, index=None):
    """Parse one or more `a.b.c=value` strings into a nested dict.

    If `index` (the config type index from `MODULE_LOADER.config_type_index`) is
    provided, each value is coerced toward its declared type so string fields keep
    their literal text and typed fields get real typed values.
    """
    result: dict = {}
    for entry in entries:
        if "=" not in entry:
            raise ValueError(f'Expected "key=value" (got {entry!r})')
        path, _, raw = entry.partition("=")
        path = path.strip()
        if not path:
            raise ValueError(f'Empty key in "{entry}"')
        adapter = index.get(path) if index is not None else None
        dotted_set(result, path, _parse_cli_value(raw.strip(), adapter))
    return result


log = logging.getLogger("bbot.presets.args")


class BBOTArgs:
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
            "A basic web scan includes robots.txt, storage buckets, IIS shortnames, and other non-intrusive web modules",
            "bbot -t evilcorp.com -p subdomain-enum web",
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
            "List output modules",
            "",
            "bbot -lo",
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
        (
            "Show help for a specific module",
            "",
            "bbot -mh <module_name>",
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
        # -t/--targets becomes target (defines target, what in_target() checks)
        # -s/--seeds becomes seeds (drives passive modules), defaults to targets if not specified
        seeds = self.parsed.seeds if self.parsed.seeds is not None else self.parsed.targets
        args_preset = self.preset.__class__(
            *(self.parsed.targets or []),
            seeds=seeds if seeds else None,
            blacklist=self.parsed.blacklist,
            name="args_preset",
        )

        # then we load requested preset
        # this is important so we can load custom module directories, pull in custom flags, module config options, etc.
        for preset_arg in self.parsed.preset:
            try:
                args_preset.include_preset(preset_arg)
            except BBOTArgumentError:
                raise
            except Exception as e:
                raise BBOTArgumentError(f'Error parsing preset "{preset_arg}": {e}')

        # then we set verbosity levels (so if the user enables -d they can see debug output)
        if self.parsed.silent:
            args_preset.silent = True
        if self.parsed.verbose:
            args_preset.verbose = True
        if self.parsed.debug:
            args_preset.debug = True

        # modules + flags
        args_preset.exclude_modules.update(set(self.parsed.exclude_modules))
        args_preset.exclude_output_modules.update(set(self.parsed.exclude_output_modules))
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
        if self.parsed.no_color:
            os.environ["NO_COLOR"] = "1"
        if self.parsed.exclude_cdn:
            args_preset.explicit_scan_modules.add("portfilter")

        # dependencies
        deps_config = args_preset.core.custom_config.get("deps", {})
        if self.parsed.retry_deps:
            deps_config["behavior"] = "retry_failed"
        elif self.parsed.force_deps:
            deps_config["behavior"] = "force_install"
        elif self.parsed.no_deps:
            deps_config["behavior"] = "disable"
        elif self.parsed.ignore_failed_deps:
            deps_config["behavior"] = "ignore_failed"
        if deps_config:
            args_preset.core.merge_custom({"deps": deps_config})

        # other scan options
        if self.parsed.name is not None:
            args_preset.scan_name = self.parsed.name
        if self.parsed.output_dir is not None:
            args_preset.output_dir = self.parsed.output_dir
        if self.parsed.force:
            args_preset.force_start = self.parsed.force

        if self.parsed.proxy:
            args_preset.core.merge_custom({"web": {"http_proxy": self.parsed.proxy}})

        if self.parsed.no_proxy:
            args_preset.core.merge_custom({"web": {"http_proxy_exclude": self.parsed.no_proxy}})

        if self.parsed.custom_headers:
            args_preset.core.merge_custom({"web": {"http_headers": self.parsed.custom_headers}})

        if self.parsed.custom_cookies:
            args_preset.core.merge_custom({"web": {"http_cookies": self.parsed.custom_cookies}})

        if self.parsed.custom_yara_rules:
            args_preset.core.merge_custom(
                {"modules": {"excavate": {"custom_yara_rules": self.parsed.custom_yara_rules}}}
            )

        if self.parsed.user_agent:
            args_preset.core.merge_custom({"web": {"user_agent": self.parsed.user_agent}})

        if self.parsed.user_agent_suffix:
            args_preset.core.merge_custom({"web": {"user_agent_suffix": self.parsed.user_agent_suffix}})

        # CLI config options (dot-syntax) -- parsed type-aware so string fields
        # keep their literal value (e.g. an all-numeric password isn't coerced to int)
        index = self._config_type_index()
        for config_arg in self.parsed.config:
            try:
                args_preset.core.merge_custom(parse_dotted_cli([config_arg], index=index))
            except Exception as e:
                raise BBOTArgumentError(f'Error parsing command-line config option: "{config_arg}": {e}')

        # strict scope
        if self.parsed.strict_scope:
            args_preset.core.merge_custom({"scope": {"strict": True}})

        return args_preset

    def create_parser(self, *args, **kwargs):
        kwargs.update(
            {
                "description": "Bighuge BLS OSINT Tool",
                "formatter_class": argparse.RawTextHelpFormatter,
                "epilog": self.epilog,
            }
        )
        p = argparse.ArgumentParser(*args, **kwargs)

        target = p.add_argument_group(title="Target")
        target.add_argument("-t", "--targets", nargs="+", default=[], help="Target scope", metavar="TARGET")
        target.add_argument(
            "-s",
            "--seeds",
            nargs="+",
            default=None,
            help="Define seeds to drive passive modules without being in scope (if not specified, defaults to same as targets)",
        )
        target.add_argument("-b", "--blacklist", nargs="+", default=[], help="Don't touch these things")
        target.add_argument(
            "--strict-scope",
            action="store_true",
            help="Don't consider subdomains of target to be in-scope - exact matches only",
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
        presets.add_argument("-lp", "--list-presets", action="store_true", help="List available presets.")

        modules = p.add_argument_group(title="Modules")
        modules.add_argument(
            "-m",
            "--modules",
            nargs="+",
            default=[],
            help=f"Modules to enable. Choices: {','.join(sorted(self.preset.module_loader.scan_module_choices))}",
            metavar="MODULE",
        )
        modules.add_argument("-l", "--list-modules", action="store_true", help="List available modules.")
        modules.add_argument(
            "-lmo", "--list-module-options", action="store_true", help="Show all module config options"
        )
        modules.add_argument(
            "-em", "--exclude-modules", nargs="+", default=[], help="Exclude these modules.", metavar="MODULE"
        )
        modules.add_argument(
            "-f",
            "--flags",
            nargs="+",
            default=[],
            help=f"Enable modules by flag. Choices: {','.join(sorted(self.preset.module_loader.flag_choices))}",
            metavar="FLAG",
        )
        modules.add_argument("-lf", "--list-flags", action="store_true", help="List available flags.")
        modules.add_argument(
            "-rf",
            "--require-flags",
            nargs="+",
            default=[],
            help="Only enable modules with these flags (e.g. -rf passive)",
            metavar="FLAG",
        )
        modules.add_argument(
            "-ef",
            "--exclude-flags",
            nargs="+",
            default=[],
            help="Disable modules with these flags. (e.g. -ef loud)",
            metavar="FLAG",
        )

        scan = p.add_argument_group(title="Scan")
        scan.add_argument("-n", "--name", help="Name of scan (default: random)", metavar="SCAN_NAME")
        scan.add_argument("-v", "--verbose", action="store_true", help="Be more verbose")
        scan.add_argument("-d", "--debug", action="store_true", help="Enable debugging")
        scan.add_argument("-S", "--silent", action="store_true", help="Be quiet")
        scan.add_argument(
            "--force",
            action="store_true",
            help="Run scan even in the case of condition violations or failed module setups",
        )
        scan.add_argument("-y", "--yes", action="store_true", help="Skip scan confirmation prompt")
        scan.add_argument(
            "--fast-mode",
            action="store_true",
            help="Scan only the provided targets as fast as possible, with no extra discovery",
        )
        scan.add_argument("--dry-run", action="store_true", help="Abort before executing scan")
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

        scan.add_argument(
            "-mh",
            "--module-help",
            default=None,
            help="Show help for a specific module",
            metavar="MODULE",
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
            help=f"Add output module(s). Choices: {','.join(sorted(self.preset.module_loader.output_module_choices))}",
            metavar="MODULE",
        )
        output.add_argument(
            "-eom",
            "--exclude-output-modules",
            nargs="+",
            default=[],
            help="Exclude output module(s)",
            metavar="MODULE",
        )
        output.add_argument("-lo", "--list-output-modules", action="store_true", help="List available output modules")
        output.add_argument("--json", "-j", action="store_true", help="Output scan data in JSON format")
        output.add_argument("--brief", "-br", action="store_true", help="Output only the data itself")
        output.add_argument("--no-color", action="store_true", help="Disable colored terminal output")
        output.add_argument("--event-types", nargs="+", default=[], help="Choose which event types to display")
        output.add_argument(
            "--exclude-cdn",
            "-ec",
            action="store_true",
            help="Filter out unwanted open ports on CDNs/WAFs (80,443 only)",
        )

        deps = p.add_argument_group(
            title="Module dependencies", description="Control how modules install their dependencies"
        )
        # Behavior flags are mutually exclusive with each other. But need to be able to be combined with --install-all-deps.
        g2 = deps.add_mutually_exclusive_group()
        g2.add_argument("--no-deps", action="store_true", help="Don't install module dependencies")
        g2.add_argument("--force-deps", action="store_true", help="Force install all module dependencies")
        g2.add_argument("--retry-deps", action="store_true", help="Try again to install failed module dependencies")
        g2.add_argument(
            "--ignore-failed-deps", action="store_true", help="Run modules even if they have failed dependencies"
        )
        deps.add_argument("--install-all-deps", action="store_true", help="Install dependencies for all modules")

        misc = p.add_argument_group(title="Misc")
        misc.add_argument("--version", action="store_true", help="show BBOT version and exit")
        misc.add_argument(
            "--reset-config",
            action="store_true",
            help="Regenerate bbot.yml from current defaults (overwrites; backs up to .bak)",
        )
        misc.add_argument(
            "--reset-secrets",
            action="store_true",
            help="Regenerate secrets.yml from current defaults (overwrites; backs up to .bak)",
        )
        misc.add_argument("--proxy", help="Use this proxy for all HTTP requests", metavar="HTTP_PROXY")
        misc.add_argument(
            "--no-proxy",
            nargs="+",
            default=[],
            help="Exclude these hosts from proxy (e.g. localhost *.internal.corp 10.0.0.0/8)",
            metavar="HOST",
        )
        misc.add_argument(
            "-H",
            "--custom-headers",
            nargs="+",
            default=[],
            help="List of custom headers as key value pairs (header=value).",
        )
        misc.add_argument(
            "-C",
            "--custom-cookies",
            nargs="+",
            default=[],
            help="List of custom cookies as key value pairs (cookie=value).",
        )
        misc.add_argument("--custom-yara-rules", "-cy", help="Add custom yara rules to excavate")

        misc.add_argument("--user-agent", "-ua", help="Set the user-agent for all HTTP requests")
        misc.add_argument(
            "--user-agent-suffix", "-uas", help="Suffix to append to the user-agent", metavar="SUFFIX", default=None
        )
        return p

    def sanitize_args(self):
        # silent implies -y
        if self.parsed.silent:
            self.parsed.yes = True
        # chain_lists allows either comma-separated or space-separated lists
        self.parsed.modules = chain_lists(self.parsed.modules)
        self.parsed.exclude_modules = chain_lists(self.parsed.exclude_modules)
        self.parsed.output_modules = chain_lists(self.parsed.output_modules)
        self.parsed.exclude_output_modules = chain_lists(self.parsed.exclude_output_modules)
        self.parsed.targets = chain_lists(
            self.parsed.targets, try_files=True, msg="Reading targets from file: {filename}", _strip_comments=True
        )
        if self.parsed.seeds is not None:
            self.parsed.seeds = chain_lists(
                self.parsed.seeds, try_files=True, msg="Reading seeds from file: {filename}", _strip_comments=True
            )
        self.parsed.blacklist = chain_lists(
            self.parsed.blacklist, try_files=True, msg="Reading blacklist from file: {filename}", _strip_comments=True
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

        # Custom Cookie Parsing / Validation
        custom_cookies_dict = {}
        custom_cookie_example = "Example: --custom-cookies foo=bar foo2=bar2"

        for i in self.parsed.custom_cookies:
            parts = i.split("=", 1)
            if len(parts) != 2:
                raise ValidationError(f"Custom cookies not formatted correctly (missing '='). {custom_cookie_example}")
            k, v = parts
            if not k or not v:
                raise ValidationError(
                    f"Custom cookies not formatted correctly (missing cookie name or value). {custom_cookie_example}"
                )
            custom_cookies_dict[k] = v
        self.parsed.custom_cookies = custom_cookies_dict

        # --fast-mode
        if self.parsed.fast_mode:
            self.parsed.preset += ["fast"]

    def _config_type_index(self):
        """Config type index for type-directed CLI parsing, or None if it can't
        be built yet (then parsing falls back to plain YAML coercion)."""
        try:
            return self.preset.module_loader.config_type_index
        except Exception:
            return None

    def validate(self):
        """
        Validate the CLI `-c key=value` arguments against the composite
        preset schema. Catches typos like `bbot -c modules.shoudn.api_key=x`
        with a closest-match suggestion.
        """
        from .validate import validate_preset

        if not self.parsed.config:
            return
        cli_dict = parse_dotted_cli(self.parsed.config, index=self._config_type_index())
        errs = validate_preset({"config": cli_dict}, module_loader=self.preset.module_loader)
        if errs:
            raise ValidationError("\n".join(str(e) for e in errs))
