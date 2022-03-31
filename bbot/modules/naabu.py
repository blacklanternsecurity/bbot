import json
import subprocess
from .base import BaseModule


class naabu(BaseModule):

    watched_events = [
        "IPV4_ADDRESS",
        "IPV6_ADDRESS",
        "IPV4_RANGE",
        "IPV6_RANGE",
        "HOSTNAME",
    ]
    produced_events = ["OPEN_TCP_PORT"]
    max_threads = 5
    batch_size = 10

    def handle_batch(self, *events):

        command = ["naabu", "-silent", "-json"] + [str(e.data) for e in events]
        self.debug(" ".join(command))
        proc = subprocess.Popen(
            command, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE
        )
        while 1:
            line = proc.stdout.readline()
            if not line:
                break
            j = json.loads(line)
            host = j.get("host", j.get("ip"))
            port = j.get("port")

            source_event = None
            for event in events:
                if host in event:
                    source_event = event
                    break

            self.emit_event(f"{host}:{port}", "OPEN_TCP_PORT", source_event)
