import json
import subprocess

from .base import BaseModule


class httpx(BaseModule):

    watched_events = ["OPEN_TCP_PORT"]
    produced_events = ["URL", "HTTP_RESPONSE"]
    flags = ["active"]
    batch_size = 100
    in_scope_only = False
    options = {"in_scope_only": True, "version": "1.2.1"}
    options_desc = {"in_scope_only": "Only visit web resources that are in scope.", "version": "httpx version"}
    deps_ansible = [
        {
            "name": "Download httpx",
            "unarchive": {
                "src": "https://github.com/projectdiscovery/httpx/releases/download/v${BBOT_MODULES_HTTPX_VERSION}/httpx_${BBOT_MODULES_HTTPX_VERSION}_linux_amd64.zip",
                "include": "httpx",
                "dest": "${BBOT_TOOLS}",
                "remote_src": True,
            },
        }
    ]
    in_scope_only = True

    def setup(self):
        self.timeout = self.scan.config.get("http_timeout", 5)
        return True

    def filter_event(self, event):
        in_scope_only = self.config.get("in_scope_only", True)
        if in_scope_only and not self.scan.target.in_scope(event):
            return False
        return True

    def handle_batch(self, *events):

        stdin = [str(e.data) for e in events]
        command = [
            "httpx",
            "-silent",
            "-json",
            "-irr",
            "-timeout",
            self.timeout,
            "-H",
            f"User-Agent: {self.scan.useragent}",
        ]
        for line in self.helpers.run_live(command, input=stdin, stderr=subprocess.DEVNULL):
            try:
                j = json.loads(line)
            except json.decoder.JSONDecodeError:
                self.debug(f"Failed to decode line: {line}")
                continue
            url = j.get("url", "")
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
            http_response_event = self.scan.make_event(j, "HTTP_RESPONSE", url_event, internal=True)
            self.emit_event(http_response_event)
            if title:
                self.emit_event(f"{title} ({url})", "HTTP_TITLE", source_event)
