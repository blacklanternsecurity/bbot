import json
import yaml
from itertools import islice
from bbot.modules.base import BaseModule


class nuclei(BaseModule):
    watched_events = ["URL"]
    produced_events = ["FINDING", "VULNERABILITY", "TECHNOLOGY"]
    flags = ["active", "aggressive", "deadly"]
    meta = {
        "description": "Fast and customisable vulnerability scanner",
        "created_date": "2022-03-12",
        "author": "@TheTechromancer",
    }

    options = {
        "version": "3.4.2",
        "tags": "",
        "templates": "",
        "severity": "",
        "ratelimit": 150,
        "concurrency": 25,
        "mode": "manual",
        "etags": "",
        "budget": 1,
        "silent": False,
        "directory_only": True,
        "retries": 0,
        "batch_size": 200,
        "module_timeout": 21600,  # 6 hours
    }
    options_desc = {
        "version": "nuclei version",
        "tags": "execute a subset of templates that contain the provided tags",
        "templates": "template or template directory paths to include in the scan",
        "severity": "Filter based on severity field available in the template.",
        "ratelimit": "maximum number of requests to send per second (default 150)",
        "concurrency": "maximum number of templates to be executed in parallel (default 25)",
        "mode": "manual | technology | severe | budget. Technology: Only activate based on technology events that match nuclei tags (nuclei -as mode). Manual (DEFAULT): Fully manual settings. Severe: Only critical and high severity templates without intrusive. Budget: Limit Nuclei to a specified number of HTTP requests",
        "etags": "tags to exclude from the scan",
        "budget": "Used in budget mode to set the number of allowed requests per host",
        "silent": "Don't display nuclei's banner or status messages",
        "directory_only": "Filter out 'file' URL event (default True)",
        "retries": "number of times to retry a failed request (default 0)",
        "batch_size": "Number of targets to send to Nuclei per batch (default 200)",
        "module_timeout": "Max time in seconds to spend handling each batch of events",
    }
    deps_ansible = [
        {
            "name": "Download nuclei",
            "unarchive": {
                "src": "https://github.com/projectdiscovery/nuclei/releases/download/v#{BBOT_MODULES_NUCLEI_VERSION}/nuclei_#{BBOT_MODULES_NUCLEI_VERSION}_#{BBOT_OS}_#{BBOT_CPU_ARCH}.zip",
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
        # attempt to update nuclei templates
        self.nuclei_templates_dir = self.helpers.tools_dir / "nuclei-templates"
        self.info("Updating Nuclei templates")
        update_results = await self.run_process(
            ["nuclei", "-update-template-dir", self.nuclei_templates_dir, "-update-templates"]
        )
        if update_results.stderr:
            if "Successfully downloaded nuclei-templates" in update_results.stderr:
                self.success("Successfully updated nuclei templates")
            elif "No new updates found for nuclei templates" in update_results.stderr:
                self.info("Nuclei templates already up-to-date")
            else:
                self.warning(f"Failure while updating nuclei templates: {update_results.stderr}")
        else:
            self.warning("Error running nuclei template update command")
        self.proxy = self.scan.web_config.get("http_proxy", "")
        self.mode = self.config.get("mode", "severe").lower()
        self.ratelimit = int(self.config.get("ratelimit", 150))
        self.concurrency = int(self.config.get("concurrency", 25))
        self.budget = int(self.config.get("budget", 1))
        self.silent = self.config.get("silent", False)
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
        self.iserver = self.scan.config.get("interactsh_server", None)
        self.itoken = self.scan.config.get("interactsh_token", None)
        self.retries = int(self.config.get("retries", 0))

        if self.mode not in ("technology", "severe", "manual", "budget"):
            self.warning(f"Unable to initialize nuclei: invalid mode selected: [{self.mode}]")
            return False

        if self.mode == "technology":
            self.info(
                "Running nuclei in TECHNOLOGY mode. Scans will only be performed with the --automatic-scan flag set. This limits the templates used to those that match wappalyzer signatures"
            )
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

            self.info("Processing nuclei templates to perform budget calculations...")

            self.nucleibudget = NucleiBudget(self)
            self.budget_templates_file = self.helpers.tempfile(self.nucleibudget.collapsible_templates, pipe=False)

            self.info(
                f"Loaded [{str(sum(self.nucleibudget.severity_stats.values()))}] templates based on a budget of [{str(self.budget)}] request(s)"
            )
            self.info(
                f"Template Severity: Critical [{self.nucleibudget.severity_stats['critical']}] High [{self.nucleibudget.severity_stats['high']}] Medium [{self.nucleibudget.severity_stats['medium']}] Low [{self.nucleibudget.severity_stats['low']}] Info [{self.nucleibudget.severity_stats['info']}] Unknown [{self.nucleibudget.severity_stats['unknown']}]"
            )

        return True

    async def handle_batch(self, *events):
        temp_target = self.helpers.make_target()
        for e in events:
            temp_target.add(e.data, e)
        nuclei_input = [str(e.data) for e in events]
        async for severity, template, tags, host, url, name, extracted_results in self.execute_nuclei(nuclei_input):
            # this is necessary because sometimes nuclei is inconsistent about the data returned in the host field
            cleaned_host = temp_target.get(host)
            parent_event = self.correlate_event(events, cleaned_host)

            if not parent_event:
                continue

            if url == "":
                url = str(parent_event.data)

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
                    },
                    "VULNERABILITY",
                    parent_event,
                    context=f"{{module}} scanned {url} and identified {severity.lower()} {{event.type}}: {description_string}",
                )

    def correlate_event(self, events, host):
        for event in events:
            if host in event:
                return event
        self.verbose(f"Failed to correlate nuclei result for {host}. Possible parent events:")
        for event in events:
            self.verbose(f" - {event.data}")

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

        for cli_option in ("severity", "templates", "iserver", "itoken", "tags", "etags"):
            option = getattr(self, cli_option)

            if option:
                command.append(f"-{cli_option}")
                command.append(option)

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
                async for line in self.run_process_live(command, input=nuclei_input, stderr=stats_fh):
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

    async def filter_event(self, event):
        if self.config.get("directory_only", True):
            if "endpoint" in event.tags:
                self.debug(
                    f"rejecting URL [{str(event.data)}] because directory_only is true and event has endpoint tag"
                )
                return False
        return True


class NucleiBudget:
    def __init__(self, nuclei_module):
        self.parent = nuclei_module
        self._yaml_files = {}
        self.templates_dir = nuclei_module.nuclei_templates_dir
        self.yaml_list = self.get_yaml_list()
        self.budget_paths = self.find_budget_paths(nuclei_module.budget)
        self.collapsible_templates, self.severity_stats = self.find_collapsible_templates()

    def get_yaml_list(self):
        return list(self.templates_dir.rglob("*.yaml"))

    # Given the current budget setting, scan all of the templates for paths, sort them by frequency and select the first N (budget) items
    def find_budget_paths(self, budget):
        path_frequency = {}
        for yf in self.yaml_list:
            if yf:
                for paths in self.get_yaml_request_attr(yf, "path"):
                    for path in paths:
                        if path in path_frequency.keys():
                            path_frequency[path] += 1
                        else:
                            path_frequency[path] = 1

        sorted_dict = dict(sorted(path_frequency.items(), key=lambda item: item[1], reverse=True))
        return list(dict(islice(sorted_dict.items(), budget)).keys())

    def get_yaml_request_attr(self, yf, attr):
        p = self.parse_yaml(yf)
        requests = p.get("http", [])
        for r in requests:
            raw = r.get("raw")
            if not raw:
                res = r.get(attr)
                if res is not None:
                    yield res

    def get_yaml_info_attr(self, yf, attr):
        p = self.parse_yaml(yf)
        info = p.get("info", [])
        res = info.get(attr)
        if res is not None:
            yield res

    # Parse through all templates and locate those which match the conditions necessary to collapse down to the budget setting
    def find_collapsible_templates(self):
        collapsible_templates = []
        severity_dict = {}
        for yf in self.yaml_list:
            valid = True
            if yf:
                for paths in self.get_yaml_request_attr(yf, "path"):
                    if set(paths).issubset(self.budget_paths):
                        headers = self.get_yaml_request_attr(yf, "headers")
                        for header in headers:
                            if header:
                                valid = False

                        method = self.get_yaml_request_attr(yf, "method")
                        for m in method:
                            if m != "GET":
                                valid = False

                        max_redirects = self.get_yaml_request_attr(yf, "max-redirects")
                        for mr in max_redirects:
                            if mr:
                                valid = False

                        redirects = self.get_yaml_request_attr(yf, "redirects")
                        for rd in redirects:
                            if rd:
                                valid = False

                        cookie_reuse = self.get_yaml_request_attr(yf, "cookie-reuse")
                        for c in cookie_reuse:
                            if c:
                                valid = False

                        if valid:
                            collapsible_templates.append(str(yf))
                            severity_gen = self.get_yaml_info_attr(yf, "severity")
                            severity = next(severity_gen)
                            if severity in severity_dict.keys():
                                severity_dict[severity] += 1
                            else:
                                severity_dict[severity] = 1
        return collapsible_templates, severity_dict

    def parse_yaml(self, yamlfile):
        if yamlfile not in self._yaml_files:
            with open(yamlfile, "r") as stream:
                try:
                    y = yaml.safe_load(stream)
                    self._yaml_files[yamlfile] = y
                except yaml.YAMLError as e:
                    self.parent.warning(f"failed to load yaml file: {e}")
                    return {}
        return self._yaml_files[yamlfile]
