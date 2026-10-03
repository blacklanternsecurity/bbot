import asyncio
import json
import os
import shutil
import yaml
from pathlib import Path
from typing import Literal
from collections import Counter

from pydantic import field_validator

from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class nuclei(BaseModule):
    watched_events = ["URL"]
    produced_events = ["FINDING", "TECHNOLOGY"]
    flags = ["active", "loud", "invasive"]
    meta = {
        "description": "Fast and customisable vulnerability scanner",
        "created_date": "2022-03-12",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        version: str = Field("3.11.1", description="nuclei version")
        tags: str = Field("", description="execute a subset of templates that contain the provided tags")
        templates: str = Field("", description="template or template directory paths to include in the scan")
        severity: str = Field("", description="Filter based on severity field available in the template.")
        ratelimit: int = Field(150, description="maximum number of requests to send per second (default 150)")
        concurrency: int = Field(25, description="maximum number of templates to be executed in parallel (default 25)")
        mode: Literal["manual", "technology", "severe", "budget"] = Field(
            "manual",
            description=(
                "manual | technology | severe | budget. "
                "Technology: Only activate based on technology events that match nuclei tags (nuclei -as mode). "
                "Manual (DEFAULT): Fully manual settings. "
                "Severe: Only critical and high severity templates without intrusive. "
                "Budget: Limit Nuclei to a specified number of HTTP requests"
            ),
        )
        etags: str = Field("", description="tags to exclude from the scan")
        exclude_severity: str = Field("", description="Filter out templates with the given severities")
        include_tags: str = Field(
            "", description="tags to run even though nuclei excludes them by default (e.g. dos, fuzz, bruteforce)"
        )
        template_ids: str = Field("", description="Only run templates with the given IDs (wildcards allowed)")
        exclude_ids: str = Field("", description="Exclude templates with the given IDs")
        protocol_types: str = Field(
            "",
            description="Only run templates of the given protocol types (http, dns, ssl, tcp, javascript, etc.)",
        )
        profile: str = Field(
            "", description="nuclei template profile to run (built-in profile id, or path to a profile file)"
        )
        template_condition: str = Field(
            "", description='expression to filter templates by, e.g. "epss_score>=0.1 && max_request<=3"'
        )
        new_templates: bool = Field(False, description="Only run templates added in the latest templates release")
        new_templates_versions: str = Field(
            "", description="Only run templates added in the given templates releases, e.g. 'v10.4.8,v10.4.9'"
        )
        budget: int = Field(1, description="Used in budget mode to set the number of allowed requests per host")
        silent: bool = Field(False, description="Don't display nuclei's banner or status messages")
        directory_only: bool = Field(True, description="Filter out 'file' URL event (default True)")
        retries: int = Field(0, description="number of times to retry a failed request (default 0)")
        batch_size: int = Field(200, description="Number of targets to send to Nuclei per batch (default 200)")
        module_timeout: int = Field(21600, description="Max time in seconds to spend handling each batch of events")

        @field_validator("severity", "exclude_severity", "protocol_types", mode="before")
        @classmethod
        def _validate_nuclei_enums(cls, value, info):
            # nuclei rejects a bad value with exit code 2, but only after the scan has started and
            # the templates have updated. Catching it here fails at preset-validation time instead.
            # These lists are literals because Config bodies are exec'd without module globals;
            # TestNucleiEnumDrift pins them against what the nuclei binary advertises.
            allowed = {
                "severity": ("info", "low", "medium", "high", "critical", "unknown"),
                "exclude_severity": ("info", "low", "medium", "high", "critical", "unknown"),
                "protocol_types": (
                    "dns",
                    "file",
                    "http",
                    "headless",
                    "tcp",
                    "workflow",
                    "ssl",
                    "websocket",
                    "whois",
                    "code",
                    "javascript",
                ),
            }[info.field_name]
            for entry in str(value or "").split(","):
                entry = entry.strip().lower()
                if entry and entry not in allowed:
                    raise ValueError(f"Invalid {info.field_name} '{entry}'. Must be one of: {', '.join(allowed)}")
            return value

    deps_ansible = [
        {
            "name": "Download nuclei",
            "unarchive": {
                "src": "https://github.com/projectdiscovery/nuclei/releases/download/v#{BBOT_MODULES_NUCLEI_VERSION}/nuclei_#{BBOT_MODULES_NUCLEI_VERSION}_#{BBOT_OS}_#{BBOT_CPU_ARCH_GOLANG}.zip",
                "include": "nuclei",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        }
    ]
    deps_pip = ["pyyaml~=6.0"]
    in_scope_only = True
    _batch_size = 200

    async def setup(self):
        # All nuclei state lives under one bbot-owned dir so we can wipe it on
        # corruption without touching the user's own ~/.config/nuclei. See
        # _nuclei_env() for how the subprocess env pins config/cache here.
        self.nuclei_state_dir = self.helpers.tools_dir / "nuclei-state"
        self.nuclei_config_dir = self.nuclei_state_dir / "config"
        self.nuclei_cache_dir = self.nuclei_state_dir / "cache"
        self.nuclei_templates_dir = self.nuclei_state_dir / "templates"
        # built-in template profiles ship inside the templates repo
        self.profiles_dir = self.nuclei_templates_dir / "profiles"
        self.nuclei_config_dir.mkdir(parents=True, exist_ok=True)
        self.nuclei_cache_dir.mkdir(parents=True, exist_ok=True)
        await self._update_templates()
        # nuclei writes its version marker before the tarball finishes extracting,
        # so a killed update can leave the marker pointing at an empty dir and
        # every subsequent run reports "up-to-date." Verify and repair once.
        if not self._templates_installed():
            self.warning("Nuclei templates appear incomplete; wiping isolated state and re-downloading")
            shutil.rmtree(self.nuclei_state_dir, ignore_errors=True)
            self.nuclei_config_dir.mkdir(parents=True, exist_ok=True)
            self.nuclei_cache_dir.mkdir(parents=True, exist_ok=True)
            await self._update_templates()
            if not self._templates_installed():
                return False, "Failed to install nuclei templates after retry"
        self.proxy = self.scan.web_config.get("http_proxy", "")
        self.mode = self.config.get("mode")
        self.ratelimit = self.config.get("ratelimit")
        self.concurrency = self.config.get("concurrency")
        self.budget = self.config.get("budget")
        self.silent = self.config.get("silent")
        self.templates = self.config.get("templates")
        if self.templates:
            self.info(f"Using custom template(s) at: [{self.templates}]")
        self.tags = self.config.get("tags")
        if self.tags:
            self.info(f"Setting the following nuclei tags: [{self.tags}]")
        self.etags = self.config.get("etags")
        if self.etags:
            self.info(f"Excluding the following nuclei tags: [{self.etags}]")
        self.severity = self.config.get("severity")
        if self.mode != "severe" and self.severity != "":
            self.info(f"Limiting nuclei templates to the following severities: [{self.severity}]")

        # straight passthrough filters; nuclei validates these values itself and exits non-zero
        for option, label in (
            ("exclude_severity", "Excluding the following severities"),
            ("include_tags", "Force-including the following tags"),
            ("template_ids", "Limiting nuclei to the following template IDs"),
            ("exclude_ids", "Excluding the following template IDs"),
            ("protocol_types", "Limiting nuclei to the following protocol types"),
        ):
            value = self.config.get(option, "")
            setattr(self, option, value)
            if value:
                self.info(f"{label}: [{value}]")

        self.profile = self.config.get("profile", "")
        if self.profile:
            # nuclei prints an FTL line for an unknown profile but still exits 0, so resolve it ourselves
            if not Path(self.profile).is_file() and not (self.profiles_dir / f"{self.profile}.yml").is_file():
                available = ", ".join(sorted(p.stem for p in self.profiles_dir.glob("*.yml")))
                return False, (
                    f"Invalid nuclei profile '{self.profile}'. Must be a path to a profile file, "
                    f"or one of: {available}"
                )
            self.info(f"Using nuclei template profile: [{self.profile}]")

        self.template_condition = self.config.get("template_condition", "")
        if self.template_condition:
            self.info(f"Filtering nuclei templates by condition: [{self.template_condition}]")
            matched = await self._count_condition_templates(self.template_condition)
            if not matched:
                return False, (
                    f"nuclei template_condition '{self.template_condition}' matched 0 templates. "
                    "Note that nuclei silently ignores unrecognized field names."
                )
            self.verbose(f"template_condition matched {matched:,} templates")

        self.new_templates = self.config.get("new_templates", False)
        self.new_templates_versions = self.config.get("new_templates_versions", "")
        if self.new_templates:
            self.info("Limiting nuclei to templates added in the latest nuclei-templates release")
        if self.new_templates_versions:
            self.info(f"Limiting nuclei to templates added in release(s): [{self.new_templates_versions}]")

        self.iserver = self.scan.config.get("interactsh_server", None)
        self.itoken = self.scan.config.get("interactsh_token", None)
        self.retries = self.config.get("retries")

        if self.mode == "technology":
            self.info(
                "Running nuclei in TECHNOLOGY mode. Scans will only be performed with the --automatic-scan flag set. This limits the templates used to those that match wappalyzer signatures"
            )
            # Don't clear user-specified tags — they act as additional filters
            # alongside -as, narrowing the auto-selected template set.
            # Only clear tags if the user didn't explicitly set them.
            if not self.tags:
                self.tags = ""

        if self.mode == "severe":
            self.info(
                "Running nuclei in SEVERE mode. Only critical and high severity templates will be used. Tag setting will be IGNORED."
            )
            self.severity = "critical,high"
            self.tags = ""

        if self.mode == "manual":
            self.info(
                "Running nuclei in MANUAL mode. Settings will be passed directly into nuclei with no modification"
            )

        if self.mode == "budget":
            self.info(
                f"Running nuclei in BUDGET mode. This mode calculates which nuclei templates can be used, constrained by your 'budget' of number of requests. Current budget is set to: {self.budget}"
            )

            summary = await self._load_template_summary()
            self.nucleibudget = NucleiBudget(summary, self.budget)
            self.budget_templates_file = self.helpers.tempfile(self.nucleibudget.collapsible_templates, pipe=False)

            stats = self.nucleibudget.severity_stats
            self.info(
                f"Loaded [{str(sum(stats.values()))}] templates based on a budget of [{str(self.budget)}] request(s)"
            )
            self.info(
                f"Template Severity: Critical [{stats['critical']}] High [{stats['high']}] Medium [{stats['medium']}] Low [{stats['low']}] Info [{stats['info']}] Unknown [{stats['unknown']}]"
            )

        return True

    async def handle_batch(self, *events):
        temp_target = self.helpers.make_target()
        for e in events:
            temp_target.add(e.url, e)
        nuclei_input = [e.url for e in events]
        async for severity, template, tags, host, url, name, extracted_results in self.execute_nuclei(nuclei_input):
            # this is necessary because sometimes nuclei is inconsistent about the data returned in the host field
            cleaned_host = temp_target.get(host)
            parent_event = self.correlate_event(events, cleaned_host)

            if not parent_event:
                continue

            if url == "":
                url = parent_event.url

            if severity == "INFO" and "tech" in tags:
                await self.emit_event(
                    {"technology": str(name).lower(), "url": url, "host": str(parent_event.host)},
                    "TECHNOLOGY",
                    parent_event,
                    context=f"{{module}} scanned {url} and identified {{event.type}}: {str(name).lower()}",
                )
                continue

            description_string = f"template: [{template}], name: [{name}]"
            if len(extracted_results) > 0:
                description_string += f" Extracted Data: [{','.join(extracted_results)}]"

            if severity in ["INFO", "UNKNOWN"]:
                await self.emit_event(
                    {
                        "host": str(parent_event.host),
                        "url": url,
                        "description": description_string,
                        "name": f"Nuclei Vuln - {name}",
                        "severity": "INFO",
                        "confidence": "HIGH",
                    },
                    "FINDING",
                    parent_event,
                    context=f"{{module}} scanned {url} and identified {{event.type}}: {description_string}",
                )
            else:
                await self.emit_event(
                    {
                        "severity": severity,
                        "host": str(parent_event.host),
                        "url": url,
                        "description": description_string,
                        "name": f"Nuclei Vuln - {name}",
                        "confidence": "HIGH",
                    },
                    "FINDING",
                    parent_event,
                    context=f"{{module}} scanned {url} and identified {severity.lower()} {{event.type}}: {description_string}",
                )

    def correlate_event(self, events, host):
        for event in events:
            if host in event:
                return event
        self.verbose(f"Failed to correlate nuclei result for {host}. Possible parent events:")
        for event in events:
            self.verbose(f" - {event.url}")

    async def execute_nuclei(self, nuclei_input):
        command = [
            "nuclei",
            "-jsonl",
            "-update-template-dir",
            self.nuclei_templates_dir,
            "-rate-limit",
            self.ratelimit,
            "-concurrency",
            self.concurrency,
            "-disable-update-check",
            "-stats-json",
            "-retries",
            self.retries,
        ]

        if self.helpers.system_resolvers:
            command += ["-r", self.helpers.resolver_file]

        for hk, hv in self.scan.custom_http_headers.items():
            command += ["-H", f"{hk}: {hv}"]

        # (module attribute, nuclei flag) -- the two differ wherever nuclei's flag is hyphenated
        for attr, flag in (
            ("severity", "severity"),
            ("templates", "templates"),
            ("iserver", "iserver"),
            ("itoken", "itoken"),
            ("tags", "tags"),
            ("etags", "etags"),
            ("exclude_severity", "exclude-severity"),
            ("include_tags", "include-tags"),
            ("template_ids", "template-id"),
            ("exclude_ids", "exclude-id"),
            ("protocol_types", "type"),
            ("profile", "profile"),
            ("template_condition", "template-condition"),
            ("new_templates_versions", "new-templates-version"),
        ):
            option = getattr(self, attr)

            if option:
                command.append(f"-{flag}")
                command.append(option)

        if self.new_templates:
            command.append("-new-templates")

        if self.scan.config.get("interactsh_disable") is True:
            self.info("Disabling interactsh in accordance with global settings")
            command.append("-no-interactsh")

        if self.mode == "technology":
            command.append("-as")

        if self.mode == "budget":
            command.append("-t")
            command.append(self.budget_templates_file)

        if self.proxy:
            command.append("-proxy")
            command.append(f"{self.proxy}")

        stats_file = self.helpers.tempfile_tail(callback=self.log_nuclei_status)
        try:
            with open(stats_file, "w") as stats_fh:
                async for line in self.run_process_live(
                    command, input=nuclei_input, stderr=stats_fh, env=self._nuclei_env()
                ):
                    try:
                        j = json.loads(line)
                    except json.decoder.JSONDecodeError:
                        self.debug(f"Failed to decode line: {line}")
                        continue

                    template = j.get("template-id", "")

                    # try to get the specific matcher name
                    name = j.get("matcher-name", "")

                    info = j.get("info", {})

                    # fall back to regular name
                    if not name:
                        self.debug(
                            f"Couldn't get matcher-name from nuclei json, falling back to regular name. Template: [{template}]"
                        )
                        name = info.get("name", "")
                    severity = info.get("severity", "").upper()
                    tags = info.get("tags", [])
                    host = j.get("host", "")
                    url = j.get("matched-at", "")
                    if not self.helpers.is_url(url):
                        url = ""

                    extracted_results = j.get("extracted-results", [])

                    if template and name and severity:
                        yield (severity, template, tags, host, url, name, extracted_results)
                    else:
                        self.debug("Nuclei result missing one or more required elements, not reporting. JSON: ({j})")
        finally:
            stats_file.unlink(missing_ok=True)

    def log_nuclei_status(self, line):
        if self.silent:
            return
        try:
            line = json.loads(line)
        except Exception:
            self.info(str(line))
            return
        duration = line.get("duration", "")
        errors = line.get("errors", "")
        hosts = line.get("hosts", "")
        matched = line.get("matched", "")
        percent = line.get("percent", "")
        requests = line.get("requests", "")
        rps = line.get("rps", "")
        templates = line.get("templates", "")
        total = line.get("total", "")
        status = f"[{duration}] | Templates: {templates} | Hosts: {hosts} | RPS: {rps} | Matched: {matched} | Errors: {errors} | Requests: {requests}/{total} ({percent}%)"
        self.info(status)

    async def cleanup(self):
        resume_file = self.helpers.current_dir / "resume.cfg"
        resume_file.unlink(missing_ok=True)

    def _nuclei_env(self):
        # Allowlist env vars: nuclei reads PDCP_API_KEY, GITHUB_TOKEN, AWS_*,
        # AZURE_*, etc. directly, so os.environ.copy() would silently change
        # its behavior (e.g. upload findings to ProjectDiscovery Cloud under
        # the user's account). XDG_{CONFIG,CACHE}_HOME pin nuclei's config and
        # cache under nuclei-state/ without inheriting the user's HOME.
        keep = {
            "PATH",
            "LD_LIBRARY_PATH",
            "LANG",
            "LC_ALL",
            "TZ",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "no_proxy",
        }
        env = {k: v for k, v in os.environ.items() if k in keep}
        env["XDG_CONFIG_HOME"] = str(self.nuclei_config_dir)
        env["XDG_CACHE_HOME"] = str(self.nuclei_cache_dir)
        return env

    async def _count_condition_templates(self, condition):
        """Ask nuclei how many templates a -template-condition expression selects.

        nuclei treats an unrecognized field name as a false match rather than an error, so a typo
        silently selects nothing. Counting up front turns that into a startup failure.
        """
        result = await self.run_process(
            [
                "nuclei",
                "-tl",
                "-no-stdin",
                "-disable-update-check",
                "-update-template-dir",
                self.nuclei_templates_dir,
                "-template-condition",
                condition,
            ],
            env=self._nuclei_env(),
        )
        return sum(1 for line in (result.stdout or "").splitlines() if line.strip().endswith(".yaml"))

    # bump when summarize_nuclei_templates() changes shape, so old cache entries get rebuilt
    _TEMPLATE_SUMMARY_VERSION = 1

    def _templates_version(self):
        config_file = self.nuclei_config_dir / "nuclei" / ".templates-config.json"
        try:
            return json.loads(config_file.read_text()).get("nuclei-templates-version", "")
        except (OSError, json.JSONDecodeError):
            return ""

    async def _load_template_summary(self):
        """Budget mode's view of the template tree, cached against the installed templates version.

        Parsing all ~13.5k templates takes about 35 seconds, and the result only changes when the
        templates do.
        """
        templates_version = self._templates_version()
        cache_key = f"nuclei_template_summary:{self._TEMPLATE_SUMMARY_VERSION}:{templates_version}"
        if templates_version:
            # the version is baked into the key, so entries only go stale when templates update
            cached = self.helpers.cache_get(cache_key, cache_hrs=24 * 365)
            if cached:
                try:
                    return json.loads(cached)
                except json.JSONDecodeError:
                    self.debug("Nuclei template summary cache is corrupt, rebuilding")
        else:
            self.debug("Could not determine nuclei templates version, skipping template summary cache")

        self.info("Processing nuclei templates to perform budget calculations...")
        summary = await self.helpers.run_in_executor_mp(
            summarize_nuclei_templates, str(self.nuclei_templates_dir), _timeout=600
        )
        if templates_version:
            self.helpers.cache_put(cache_key, json.dumps(summary))
        return summary

    async def _update_templates(self):
        self.info("Updating Nuclei templates")
        # shield so an outer cancel can't kill the subprocess mid-extract and
        # corrupt the templates dir
        update_results = await asyncio.shield(
            self.run_process(
                ["nuclei", "-update-template-dir", self.nuclei_templates_dir, "-update-templates"],
                env=self._nuclei_env(),
            )
        )
        outcome = self._classify_update_stderr(update_results.stderr)
        if outcome == "updated":
            self.success("Successfully updated nuclei templates")
        elif outcome == "up-to-date":
            self.info("Nuclei templates already up-to-date")
        else:
            self.warning(f"Failure while updating nuclei templates: {update_results.stderr or '<no stderr>'}")

    # nuclei's success messaging has drifted across releases (installed / updated /
    # downloaded). Match any of them so a future rename doesn't silently downgrade
    # a clean install to a "Failure while updating" warning.
    _UPDATE_SUCCESS_MARKERS = (
        "Successfully installed nuclei-templates",
        "Successfully updated nuclei-templates",
        "Successfully downloaded nuclei-templates",
    )
    _UPDATE_NOOP_MARKER = "No new updates found for nuclei templates"

    @classmethod
    def _classify_update_stderr(cls, stderr):
        if not stderr:
            return "failure"
        if any(m in stderr for m in cls._UPDATE_SUCCESS_MARKERS):
            return "updated"
        if cls._UPDATE_NOOP_MARKER in stderr:
            return "up-to-date"
        return "failure"

    def _templates_installed(self):
        http_dir = self.nuclei_templates_dir / "http"
        return http_dir.is_dir() and any(http_dir.iterdir())

    async def filter_event(self, event):
        if self.config.get("directory_only", True):
            if "endpoint" in event.tags:
                self.debug(f"rejecting URL [{event.url}] because directory_only is true and event has endpoint tag")
                return False
        return True


def summarize_nuclei_templates(templates_dir):
    """Reduce every nuclei template to the minimal shape budget mode needs.

    Runs in a subprocess via run_in_executor_mp, so it lives at module level and returns plain data.
    """
    summary = {}
    for yf in Path(templates_dir).rglob("*.yaml"):
        try:
            parsed = yaml.safe_load(yf.read_text(errors="ignore"))
        except (yaml.YAMLError, OSError):
            continue
        if not isinstance(parsed, dict):
            continue
        blocks = []
        has_raw = False
        for request in parsed.get("http") or []:
            if not isinstance(request, dict):
                continue
            if request.get("raw"):
                has_raw = True
                continue
            # a request is "clean" if nuclei can merge it with an identical one from another template
            clean = not any(
                (
                    request.get("headers"),
                    request.get("method", "GET") != "GET",
                    request.get("max-redirects"),
                    request.get("redirects"),
                    request.get("cookie-reuse"),
                )
            )
            blocks.append({"paths": list(request.get("path") or []), "clean": clean})
        if not blocks:
            continue
        info = parsed.get("info")
        severity = info.get("severity", "unknown") if isinstance(info, dict) else "unknown"
        summary[str(yf)] = {"severity": severity, "has_raw": has_raw, "blocks": blocks}
    return summary


class NucleiBudget:
    """Select the templates that collapse onto the fewest distinct requests.

    nuclei merges templates that issue identical requests, so keeping only templates whose paths are
    all drawn from the N most common paths in the tree holds the request count near N however many
    templates are selected.
    """

    def __init__(self, summary, budget):
        self.summary = summary
        self.budget_paths = self.find_budget_paths(budget)
        self.collapsible_templates, self.severity_stats = self.find_collapsible_templates()

    def find_budget_paths(self, budget):
        """The `budget` most common request paths across the whole template tree."""
        path_frequency = Counter()
        for template in self.summary.values():
            for block in template["blocks"]:
                path_frequency.update(block["paths"])
        return {path for path, _ in path_frequency.most_common(budget)}

    def find_collapsible_templates(self):
        collapsible_templates = []
        severity_stats = Counter()
        for template_path, template in sorted(self.summary.items()):
            # nuclei runs every request block in a template, not just the one that fit the budget,
            # so a template only counts as collapsible if all of its blocks do
            if template["has_raw"]:
                continue
            if not all(
                block["clean"] and set(block["paths"]).issubset(self.budget_paths) for block in template["blocks"]
            ):
                continue
            collapsible_templates.append(template_path)
            severity_stats[template["severity"]] += 1
        return collapsible_templates, severity_stats
