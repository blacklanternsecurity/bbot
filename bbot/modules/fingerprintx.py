import json
import subprocess
from bbot.modules.base import BaseModule


class fingerprintx(BaseModule):

    watched_events = ["OPEN_TCP_PORT"]
    produced_events = ["PROTOCOL"]
    flags = ["active", "safe", "service-enum"]
    meta = {"description": "Fingerprint exposed services like RDP, SSH, MySQL, etc."}
    options = {"version": "1.1.4"}
    options_desc = {"version": "fingerprintx version"}
    batch_size = 100
    _priority = 2

    deps_ansible = [
        {
            "name": "Download fingerprintx",
            "unarchive": {
                "src": "https://github.com/praetorian-inc/fingerprintx/releases/download/v#{BBOT_MODULES_FINGERPRINTX_VERSION}/fingerprintx_#{BBOT_MODULES_FINGERPRINTX_VERSION}_linux_amd64.tar.gz",
                "include": "fingerprintx",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        },
    ]

    def handle_batch(self, *events):

        _input = {e.data: e for e in events}
        command = ["fingerprintx", "--json"]
        for line in self.helpers.run_live(command, input=list(_input), stderr=subprocess.DEVNULL):
            try:
                j = json.loads(line)
            except Exception as e:
                self.debug(f'Error parsing line "{line}" as JSON: {e}')
                break
            host = j.get("host", j.get("ip", ""))
            port = str(j.get("port", ""))
            banner = j.get("metadata", {}).get("banner", "").strip()
            port_data = f"{host}:{port}"
            protocol = j.get("protocol", "")
            if host and port and protocol:
                source_event = _input.get(port_data)
                protocol_data = {"host": port_data, "protocol": protocol.upper()}
                if banner:
                    protocol_data["banner"] = banner
                self.emit_event(protocol_data, "PROTOCOL", source=source_event)
