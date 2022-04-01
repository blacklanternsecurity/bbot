import json
import subprocess
from .base import BaseModule


class naabu(BaseModule):

    watched_events = [
        "IPV4_ADDRESS",
        "IPV6_ADDRESS",
        "IPV4_RANGE",
        "IPV6_RANGE",
        "DNS_NAME",
    ]
    produced_events = ["OPEN_TCP_PORT"]
    max_threads = 5
    batch_size = 10
    in_scope_only = True

    def handle_batch(self, *events):

        command = ["naabu", "-silent", "-json"] + [str(e.data) for e in events]
        self.debug(" ".join(command))
        for line in self.helpers.run_live(command, stderr=subprocess.DEVNULL):
            try:
                j = json.loads(line)
            except Exception as e:
                self.debug(f'Error parsing line "{line}" as JSON: {e}')
            host = j.get("host", j.get("ip"))
            port = j.get("port")

            source_event = None
            for event in events:
                if host in event:
                    source_event = event
                    break

            self.emit_event(f"{host}:{port}", "OPEN_TCP_PORT", source_event)
