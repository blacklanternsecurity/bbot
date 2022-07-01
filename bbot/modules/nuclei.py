import json
import subprocess

from .base import BaseModule


class nuclei(BaseModule):

    watched_events = ["URL"]
    produced_events = ["VULNERABILITY"]
    flags = ["active"]
    max_threads = 5
    batch_size = 10
    options = {
        "version": "2.7.3",
        "tags": "",
        "templates": "",
        "severity": "",
        "disable_interactsh": False,
        "iserver": "",
        "itoken": "",
        "ratelimit": 150,
        "concurrency": 25,
    }
    options_desc = {
        "version": "nuclei version",
        "tags": "execute a subset of templates that contain the provided tags",
        "templates": "template or template directory paths to include in the scan",
        "severity": "Filter based on severity field available in the template.",
        "disable_interactsh": "disable interactsh server for OAST testing, exclude OAST based templates",
        "iserver": "interactsh server url for self-hosted instance (default https://interactsh.com)",
        "itoken": "authentication token for self-hosted interactsh server",
        "ratelimit": "maximum number of requests to send per second (default 150)",
        "concurrency": "maximum number of templates to be executed in parallel (default 25)",
    }
    deps_ansible = [
        {
            "name": "Download nuclei",
            "unarchive": {
                "src": "https://github.com/projectdiscovery/nuclei/releases/download/v${BBOT_MODULES_NUCLEI_VERSION}/nuclei_${BBOT_MODULES_NUCLEI_VERSION}_linux_amd64.zip",
                "include": "nuclei",
                "dest": "${BBOT_TOOLS}",
                "remote_src": True,
            },
        }
    ]
    in_scope_only = True

    def setup(self):

        self.templates = self.config.get("templates")
        self.tags = self.config.get("tags")
        self.severity = self.config.get("severity")
        self.iserver = self.config.get("iserver")
        self.itoken = self.config.get("itoken")
        return True

    def handle_batch(self, *events):
        """
        {
          "template": "technologies/tech-detect.yaml",
          "template-url": "https://github.com/projectdiscovery/nuclei-templates/blob/master/technologies/tech-detect.yaml",
          "template-id": "tech-detect",
          "info": {
            "name": "Wappalyzer Technology Detection",
            "author": [
              "hakluke"
            ],
            "tags": [
              "tech"
            ],
            "reference": null,
            "severity": "info"
          },
          "matcher-name": "google-font-api",
          "type": "http",
          "host": "https://www.blacklanternsecurity.com",
          "matched-at": "https://www.blacklanternsecurity.com",
          "ip": "185.199.108.153",
          "timestamp": "2022-03-11T09:54:26.562247694-05:00",
          "curl-command": "curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36' 'https://www.blacklanternsecurity.com'",
          "matcher-status": true,
          "matched-line": null
        }
        """

        _input = [str(e.data) for e in events]
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
        ]

        if self.severity:
            command.append("-severity")
            command.append(self.severity)

        if self.templates:
            command.append("-templates")
            command.append(self.templates)

        if self.iserver:
            command.append("-iserver")
            command.append(self.iserver)

        if self.itoken:
            command.append("-itoken")
            command.append(self.itoken)

        if self.tags:
            command.append("-tags")
            command.append(self.tags)

        if self.config.get("disable_interactsh") == True:
            command.append("-no-interactsh")

        for line in self.helpers.run_live(command, input=_input, stderr=subprocess.DEVNULL):
            try:
                j = json.loads(line)
            except json.decoder.JSONDecodeError:
                self.debug(f"Failed to decode line: {line}")
                continue
            template = j.get("template-id", "")
            name = j.get("matcher-name", "")
            severity = j.get("info", {}).get("severity", "").upper()
            host = j.get("host", "")

            source_event = None
            if template and name and severity and host:
                for event in events:
                    if host in event:
                        source_event = event
                        break

                self.emit_event(f"[{severity}] {template}:{name}", "VULNERABILITY", source_event)
