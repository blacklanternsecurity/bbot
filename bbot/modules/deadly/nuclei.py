import json
import yaml
from itertools import islice
from bbot.modules.base import BaseModule


class nuclei(BaseModule):
    watched_events = ["URL", "TECHNOLOGY"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "aggressive", "web-advanced"]
    meta = {"description": "Fast and customisable vulnerability scanner"}

    batch_size = 100
    options = {
        "version": "2.7.9",
        "tags": "",
        "templates": "",
        "severity": "",
        "ratelimit": 150,
        "concurrency": 25,
        "mode": "severe",
        "etags": "intrusive",
        "budget": 1,
    }
    options_desc = {
        "version": "nuclei version",
        "tags": "execute a subset of templates that contain the provided tags",
        "templates": "template or template directory paths to include in the scan",
        "severity": "Filter based on severity field available in the template.",
        "ratelimit": "maximum number of requests to send per second (default 150)",
        "concurrency": "maximum number of templates to be executed in parallel (default 25)",
        "mode": "technology | severe | manual | budget. Technology: Only activate based on technology events that match nuclei tags (nuclei -as mode). Severe (DEFAULT): Only critical and high severity templates without intrusive. Manual: Fully manual settings. Budget: Limit Nuclei to a specified number of HTTP requests",
        "etags": "tags to exclude from the scan",
        "budget": "Used in budget mode to set the number of requests which will be alloted to the nuclei scan",
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
    deps_pip = ["pyyaml"]
    in_scope_only = True

    def setup(self):
        # attempt to update nuclei templates
        self.nuclei_templates_dir = self.helpers.tools_dir / "nuclei-templates"
        self.info("Updating Nuclei templates")
        update_results = self.helpers.run(
            ["nuclei", "-update-directory", self.nuclei_templates_dir, "-update-templates"]
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

        self.mode = self.config.get("mode", "severe")
        self.ratelimit = int(self.config.get("ratelimit", 150))
        self.concurrency = int(self.config.get("concurrency", 25))
        self.budget = int(self.config.get("budget", 1))
        self.templates = self.config.get("templates")
        self.tags = self.config.get("tags")
        self.etags = self.config.get("etags")
        self.severity = self.config.get("severity")
        self.iserver = self.scan.config.get("interactsh_server", None)
        self.itoken = self.scan.config.get("interactsh_token", None)

        if self.mode not in ("technology", "severe", "manual", "budget"):
            self.warning(f"Unable to intialize nuclei: invalid mode selected: [{self.mode}]")
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

            self.nucleibudget = NucleiBudget(self.budget, self.nuclei_templates_dir)
            self.budget_templates_file = self.helpers.tempfile(self.nucleibudget.collapsable_templates, pipe=False)

            self.info(
                f"Loaded [{str(sum(self.nucleibudget.severity_stats.values()))}] templates based on a budget of [{str(self.budget)}] request(s)"
            )
            self.info(
                f"Template Severity: Critical [{self.nucleibudget.severity_stats['critical']}] High [{self.nucleibudget.severity_stats['high']}] Medium [{self.nucleibudget.severity_stats['medium']}] Low [{self.nucleibudget.severity_stats['low']}] Info [{self.nucleibudget.severity_stats['info']}] Unknown [{self.nucleibudget.severity_stats['unknown']}]"
            )

        self.stats_file = self.helpers.tempfile_tail(callback=self.log_nuclei_status)

        return True

    def handle_batch(self, *events):
        nuclei_input = [str(e.data) for e in events]
        for severity, template, host, name, extracted_results in self.execute_nuclei(nuclei_input):
            source_event = self.correlate_event(events, host)
            if source_event == None:
                continue

            description_string = f"template: [{template}], name: [{name}]"
            if len(extracted_results) > 0:
                description_string += f" Extracted Data: [{','.join(extracted_results)}]"

            if severity == "INFO":
                self.emit_event(
                    {
                        "host": str(source_event.host),
                        "url": host,
                        "description": description_string,
                    },
                    "FINDING",
                    source_event,
                )
            else:
                self.emit_event(
                    {
                        "severity": severity,
                        "host": str(source_event.host),
                        "url": host,
                        "description": description_string,
                    },
                    "VULNERABILITY",
                    source_event,
                )

    def correlate_event(self, events, host):
        for event in events:
            if host in event:
                return event
        self.warning("Failed to correlate nuclei result with event")

    def execute_nuclei(self, nuclei_input):
        command = [
            "nuclei",
            "-json",
            "-update-directory",
            self.nuclei_templates_dir,
            "-rate-limit",
            self.ratelimit,
            "-concurrency",
            self.concurrency,
            "-disable-update-check",
            "-stats-json",
            # "-r",
            # self.helpers.resolver_file,
        ]

        for cli_option in ("severity", "templates", "iserver", "itoken", "tags", "etags"):
            option = getattr(self, cli_option)

            if option:
                command.append(f"-{cli_option}")
                command.append(option)

        if self.scan.config.get("interactsh_disable") == True:
            self.info("Disbling interactsh in accordance with global settings")
            command.append("-no-interactsh")

        if self.mode == "technology":
            command.append("-as")

        if self.mode == "budget":
            command.append("-t")
            command.append(self.budget_templates_file)

        with open(self.stats_file, "w") as stats_file:
            for line in self.helpers.run_live(command, input=nuclei_input, stderr=stats_file):
                try:
                    j = json.loads(line)
                except json.decoder.JSONDecodeError:
                    self.debug(f"Failed to decode line: {line}")
                    continue

                template = j.get("template-id", "")

                # try to get the specific matcher name
                name = j.get("matcher-name", "")

                # fall back to regular name
                if not name:
                    self.debug(
                        f"Couldn't get matcher-name from nuclei json, falling back to regular name. Template: [{template}]"
                    )
                    name = j.get("info", {}).get("name", "")

                severity = j.get("info", {}).get("severity", "").upper()
                host = j.get("host", "")

                extracted_results = j.get("extracted-results", [])

                if template and name and severity and host:
                    yield (severity, template, host, name, extracted_results)
                else:
                    self.debug("Nuclei result missing one or more required elements, not reporting. JSON: ({j})")

    def log_nuclei_status(self, line):
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

    def cleanup(self):
        resume_file = self.helpers.current_dir / "resume.cfg"
        resume_file.unlink(missing_ok=True)


class NucleiBudget:
    def __init__(self, budget, templates_dir):
        self.templates_dir = templates_dir
        self.yaml_list = self.get_yaml_list()
        self.budget_paths = self.find_budget_paths(budget)
        self.collapsable_templates, self.severity_stats = self.find_collapsable_templates()

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
        requests = p.get("requests", [])
        for r in requests:
            raw = r.get("raw")
            if not raw:
                res = r.get(attr)
                yield res

    def get_yaml_info_attr(self, yf, attr):
        p = self.parse_yaml(yf)
        info = p.get("info", [])
        res = info.get(attr)
        yield res

    # Parse through all templates and locate those which match the conditions necessary to collapse down to the budget setting
    def find_collapsable_templates(self):
        collapsable_templates = []
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
                            collapsable_templates.append(str(yf))
                            severity_gen = self.get_yaml_info_attr(yf, "severity")
                            severity = next(severity_gen)
                            if severity in severity_dict.keys():
                                severity_dict[severity] += 1
                            else:
                                severity_dict[severity] = 1
        return collapsable_templates, severity_dict

    def parse_yaml(self, yamlfile):
        with open(yamlfile, "r") as stream:
            try:
                y = yaml.safe_load(stream)
                return y
            except yaml.YAMLError as e:
                self.debug(f"failed to read yaml file: {e}")
