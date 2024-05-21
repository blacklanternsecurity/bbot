import json
import subprocess
from bbot.modules.base import BaseModule


class fingerprintx(BaseModule):
    watched_events = ["OPEN_TCP_PORT"]
    produced_events = ["PROTOCOL"]
    flags = ["active", "safe", "service-enum", "slow"]
    meta = {
        "description": "Fingerprint exposed services like RDP, SSH, MySQL, etc.",
        "created_date": "2023-01-30",
        "author": "@TheTechromancer",
    }
    options = {"version": "1.1.4"}
    options_desc = {"version": "fingerprintx version"}
    _batch_size = 10
    _max_event_handlers = 2
    _priority = 2

    deps_ansible = [
        {
            "name": "Download fingerprintx",
            "unarchive": {
                "src": "https://github.com/praetorian-inc/fingerprintx/releases/download/v#{BBOT_MODULES_FINGERPRINTX_VERSION}/fingerprintx_#{BBOT_MODULES_FINGERPRINTX_VERSION}_#{BBOT_OS_PLATFORM}_#{BBOT_CPU_ARCH}.tar.gz",
                "include": "fingerprintx",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        },
    ]

    async def handle_batch(self, *events):
        _input = {e.data: e for e in events}
        command = ["fingerprintx", "--json"]
        async for line in self.run_process_live(command, input=list(_input), stderr=subprocess.DEVNULL):
            try:
                j = json.loads(line)
            except Exception as e:
                self.debug(f'Error parsing line "{line}" as JSON: {e}')
                break
            ip = j.get("ip", "")
            host = j.get("host", ip)
            port = str(j.get("port", ""))
            banner = j.get("metadata", {}).get("banner", "").strip()
            if port:
                port_data = f"{host}:{port}"
            protocol = j.get("protocol", "")
            tags = set()
            if host and ip:
                tags.add(f"ip-{ip}")
            if host and port and protocol:
                source_event = _input.get(port_data)
                protocol_data = {"host": host, "protocol": protocol.upper()}
                if port:
                    protocol_data["port"] = port
                if banner:
                    protocol_data["banner"] = banner
                await self.emit_event(protocol_data, "PROTOCOL", source=source_event, tags=tags)
