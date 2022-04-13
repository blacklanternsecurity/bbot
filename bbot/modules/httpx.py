import json
import subprocess

from .base import BaseModule


class httpx(BaseModule):

    watched_events = ["OPEN_TCP_PORT", "IP_ADDRESS", "DNS_NAME"]
    produced_events = ["URL"]
    max_threads = 2
    batch_size = 10

    options = {"allow_skip_portscan": True}

    options_desc = {"allow_skip_portscan": "Allow ingest from non-portscan even types (IP and DNS)"}

    def handle_batch(self, *events):

        stdin = "\n".join([str(e.data) for e in events])
        command = ["httpx", "-silent", "-json"]
        for line in self.helpers.run_live(command, input=stdin, stderr=subprocess.DEVNULL):
            j = json.loads(line)
            url = j.get("url")
            title = j.get("title", "")
            source_event = None
            for event in events:
                if url in event:
                    source_event = event
                    break

            if source_event is None:
                self.debug(f"Unable to correlate source event from: {line}")
                continue

            url_event = self.scan.make_event(url, "URL", source_event)
            self.emit_event(url_event)
            http_response_event = self.scan.make_event(j, "HTTP_RESPONSE", url_event)
            self.emit_event(http_response_event)
            if title:
                self.emit_event(title, "HTTP_TITLE", source_event)

    def filter_event(self, event):

        allow_skip_portscan = self.config.get("allow_skip_portscan", False)

        if event.type == "OPEN_TCP_PORT":
            return True

        if not allow_skip_portscan:
            return False
        else:
            return True
