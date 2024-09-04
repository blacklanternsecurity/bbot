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
    _module_threads = 2
    _priority = 2

    options = {"skip_common_web": True}
    options_desc = {"skip_common_web": "Skip common web ports such as 80, 443, 8080, 8443, etc."}

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

    common_web_ports = (
        80,
        443,
        # cloudflare HTTP
        8080,
        8880,
        2052,
        2082,
        2086,
        2095,
        # cloudflare HTTPS
        2053,
        2083,
        2087,
        2096,
        8443,
    )

    async def setup(self):
        self.skip_common_web = self.config.get("skip_common_web", True)
        return True

    async def filter_event(self, event):
        if self.skip_common_web:
            port_str = str(event.port)
            if event.port in self.common_web_ports or any(port_str.endswith(x) for x in ("080", "443")):
                return False, "port is a common web port and skip_common_web=True"
        return True

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
            protocol = j.get("protocol", "").upper()
            if not host and port and protocol:
                continue
            banner = j.get("metadata", {}).get("banner", "").strip()
            port_data = f"{host}:{port}"
            tags = set()
            if host and ip:
                tags.add(f"ip-{ip}")
            parent_event = _input.get(port_data)
            protocol_data = {"host": host, "protocol": protocol}
            if port:
                protocol_data["port"] = port
            if banner:
                protocol_data["banner"] = banner
            await self.emit_event(
                protocol_data,
                "PROTOCOL",
                parent=parent_event,
                tags=tags,
                context=f"{{module}} probed {port_data} and detected {{event.type}}: {protocol}",
            )
