import json
import subprocess
from .base import BaseModule


class naabu(BaseModule):

    watched_events = [
        "IP_ADDRESS",
        "DNS_NAME",
    ]
    options = {
        "version": "2.0.5",
    }
    options_desc = {
        "version": "naabu version",
    }
    produced_events = ["OPEN_TCP_PORT"]
    max_threads = 5
    batch_size = 10
    in_scope_only = True

    deps_apt = ["libpcap-dev"]
    deps_ansible = [
        {
            "name": "Download naabu",
            "unarchive": {
                "src": "https://github.com/projectdiscovery/naabu/releases/download/v${BBOT_MODULES_NAABU_VERSION}/naabu_${BBOT_MODULES_NAABU_VERSION}_linux_amd64.zip",
                "include": "naabu",
                "dest": "${BBOT_TOOLS}",
                "remote_src": True,
            },
        }
    ]

    def handle_batch(self, *events):

        _input = [str(e.data) for e in events]
        command = ["naabu", "-silent", "-json"]
        for line in self.helpers.run_live(command, input=_input, stderr=subprocess.DEVNULL):
            try:
                j = json.loads(line)
            except Exception as e:
                self.debug(f'Error parsing line "{line}" as JSON: {e}')
                break
            host = j.get("host", j.get("ip"))
            port = j.get("port")

            source_event = None
            # check exact matches first
            for event in events:
                if host == str(event.host):
                    source_event = event
                    break
            # then make a broader check, for cidrs etc.
            if source_event is None:
                for event in events:
                    if host in event:
                        source_event = event
                        break

            self.emit_event(f"{host}:{port}", "OPEN_TCP_PORT", source_event)
