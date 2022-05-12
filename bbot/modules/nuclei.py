import json
import subprocess

from .base import BaseModule


class nuclei(BaseModule):

    watched_events = ["URL"]
    produced_events = ["VULNERABILITY"]
    max_threads = 5
    batch_size = 10
    in_scope_only = True
    options = {"version": "2.7.0"}
    options_desc = {"version": "nuclei version"}
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
        command = ["nuclei", "-silent", "-json", "-tags", "tech"]
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
