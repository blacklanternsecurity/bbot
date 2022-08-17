import json
import subprocess

from bbot.modules.base import BaseModule


technology_map = {"f5 bigip": "bigip", "microsoft asp.net": "asp"}


class nuclei(BaseModule):

    watched_events = ["URL", "TECHNOLOGY"]
    produced_events = ["VULNERABILITY"]
    flags = ["active", "aggressive", "web"]
    meta = {"description": "Fast and customisable vulnerability scanner"}

    batch_size = 100
    options = {
        "version": "2.7.3",
        "tags": "",
        "templates": "",
        "severity": "",
        "ratelimit": 150,
        "concurrency": 25,
        "mode": "severe",
        "etags": "intrusive",
    }
    options_desc = {
        "version": "nuclei version",
        "tags": "execute a subset of templates that contain the provided tags",
        "templates": "template or template directory paths to include in the scan",
        "severity": "Filter based on severity field available in the template.",
        "ratelimit": "maximum number of requests to send per second (default 150)",
        "concurrency": "maximum number of templates to be executed in parallel (default 25)",
        "mode": "technology | severe | manual. Technology: Only activate based on technology events that match nuclei tags. On by default. Severe: Only critical and high severity templates without intrusive. Manual: Fully manual settings",
        "etags": "tags to exclude from the scan",
    }
    deps_ansible = [
        {
            "name": "Download nuclei",
            "unarchive": {
                "src": "https://github.com/projectdiscovery/nuclei/releases/download/v{BBOT_MODULES_NUCLEI_VERSION}/nuclei_{BBOT_MODULES_NUCLEI_VERSION}_linux_amd64.zip",
                "include": "nuclei",
                "dest": "{BBOT_TOOLS}",
                "remote_src": True,
            },
        }
    ]
    in_scope_only = True

    def setup(self):

        self.templates = self.config.get("templates")
        self.tags = self.config.get("tags")
        self.etags = self.config.get("etags")
        self.severity = self.config.get("severity")
        self.iserver = self.scan.config.get("interactsh_server", None)
        self.itoken = self.scan.config.get("interactsh_token", None)

        self.template_stats = self.helpers.download(
            "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/master/TEMPLATES-STATS.json",
            cache_hrs=72,
        )
        if not self.template_stats:
            self.warning(f"Failed to download nuclei template stats.")
            if self.config.get("mode ") == "technology":
                self.warning("Can't run with technology_mode set to true without template tags JSON")
                return False
        else:
            with open(self.template_stats) as f:
                self.template_stats_json = json.load(f)
                try:
                    self.tag_list = [e.get("name", "") for e in self.template_stats_json.get("tags", [])]
                except Exception as e:
                    self.warning(f"Failed to parse template stats: {e}")
                    return False

        if self.config.get("mode") not in ("technology", "severe", "manual"):
            self.warning(f"Unable to intialize nuclei: invalid mode selected: [{self.config.get('mode')}]")
            return False

        if self.config.get("mode") == "technology":
            self.info(
                "Running nuclei in TECHNOLOGY mode. Scans will only be performed against detected TECHNOLOGY events that match nuclei template tags"
            )
            if "wappalyzer" not in self.scan.modules:
                self.hugewarning(
                    "You are running nuclei in technology mode without wappalyzer to emit technologies. It will never execute unless another module is issuing technologies"
                )

        if self.config.get("mode") == "severe":
            self.info(
                "Running nuclei in SEVERE mode. Only critical and high severity templates will be used. Tag setting will be IGNORED."
            )
            self.severity = "critical,high"
            self.tags = ""

        if self.config.get("mode") == "manual":
            self.info(
                "Running nuclei in MANUAL mode. Settings will be passed directly into nuclei with no modification"
            )
        return True

    def handle_batch(self, *events):

        if self.config.get("mode") == "technology":

            tags_to_scan = {}
            for e in events:
                if e.type == "TECHNOLOGY":
                    reported_tag = e.data.get("technology", "")
                    if reported_tag in technology_map.keys():
                        reported_tag = technology_map[reported_tag]
                    if reported_tag in self.tag_list:
                        tag = e.data.get("technology", "")
                        if tag not in tags_to_scan.keys():
                            tags_to_scan[tag] = [e]
                        else:
                            tags_to_scan[tag].append(e)

            self.debug(f"finished processing this batch's tags with {str(len(tags_to_scan.keys()))} total tags")

            for t in tags_to_scan.keys():
                nuclei_input = [e.data["url"] for e in tags_to_scan[t]]
                taglist = self.tags.split(",")
                taglist.append(t)
                override_tags = ",".join(taglist).lstrip(",")
                self.verbose(f"Running nuclei against {str(len(nuclei_input))} host(s) with the {t} tag")
                for severity, template, host, name in self.execute_nuclei(nuclei_input, override_tags=override_tags):
                    source_event = self.correlate_event(events, host)
                    if source_event == None:
                        continue
                    self.emit_event(
                        {
                            "severity": severity,
                            "host": str(source_event.host),
                            "url": host,
                            "description": f"template: {template}, name: {name}",
                        },
                        "VULNERABILITY",
                        source_event,
                    )

        else:
            nuclei_input = [str(e.data) for e in events]
            for severity, template, host, name in self.execute_nuclei(nuclei_input):
                source_event = self.correlate_event(events, host)
                if source_event == None:
                    continue
                self.emit_event(
                    {
                        "severity": severity,
                        "host": str(source_event.host),
                        "url": host,
                        "description": f"template: {template}, name: {name}",
                    },
                    "VULNERABILITY",
                    source_event,
                )

    def correlate_event(self, events, host):
        for event in events:
            if host in event:
                return event
        self.warning("Failed to correlate nuclei result with event")

    def execute_nuclei(self, nuclei_input, override_tags=""):

        command = [
            "nuclei",
            "-silent",
            "-json",
            "-update-directory",
            f"{self.helpers.tools_dir}/nuclei-templates",
            "-rate-limit",
            self.config.get("ratelimit"),
            "-concurrency",
            str(self.config.get("concurrency")),
            # "-r",
            # self.helpers.resolver_file,
        ]

        for cli_option in ("severity", "templates", "iserver", "itoken", "etags"):
            option = getattr(self, cli_option)

            if option:
                command.append(f"-{cli_option}")
                command.append(option)

        if override_tags:
            command.append(f"-tags")
            command.append(override_tags)
        else:
            setup_tags = getattr(self, "tags")
            if setup_tags:
                command.append(f"-tags")
                command.append(setup_tags)

        if self.scan.config.get("interactsh_disable") == True:
            self.info("Disbling interactsh in accordance with global settings")
            command.append("-no-interactsh")

        for line in self.helpers.run_live(command, input=nuclei_input, stderr=subprocess.DEVNULL):
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

            if template and name and severity and host:
                yield (severity, template, host, name)
            else:
                self.debug("Nuclei result missing one or more required elements, not reporting. JSON: ({j})")

    def cleanup(self):
        resume_file = self.helpers.current_dir / "resume.cfg"
        resume_file.unlink(missing_ok=True)
