import json
import subprocess
from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class fingerprintx(BaseModule):
    watched_events = ["OPEN_TCP_PORT"]
    produced_events = ["PROTOCOL", "URL_UNVERIFIED"]
    flags = ["safe", "active", "service-enum", "slow"]
    meta = {
        "description": "Fingerprint exposed services like RDP, SSH, MySQL, etc.",
        "created_date": "2023-01-30",
        "author": "@TheTechromancer",
    }
    _batch_size = 10
    _module_threads = 2
    _priority = 2

    class Config(BaseModuleConfig):
        version: str = Field("1.1.4", description="fingerprintx version")
        skip_common_web: bool = Field(True, description="Skip common web ports such as 80, 443, 8080, 8443, etc.")

    deps_ansible = [
        {
            "name": "Download fingerprintx",
            "unarchive": {
                "src": "https://github.com/praetorian-inc/fingerprintx/releases/download/v#{BBOT_MODULES_FINGERPRINTX_VERSION}/fingerprintx_#{BBOT_MODULES_FINGERPRINTX_VERSION}_#{BBOT_OS_PLATFORM}_#{BBOT_CPU_ARCH_GOLANG}.tar.gz",
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
            port_data = self.helpers.make_netloc(host, port)
            tags = set()
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
            if protocol in ("HTTP", "HTTPS"):
                port_int = int(port) if port else None
                is_default_port = (protocol == "HTTP" and port_int == 80) or (protocol == "HTTPS" and port_int == 443)
                netloc = self.helpers.make_netloc(host, None if is_default_port else port_int)
                url = f"{protocol.lower()}://{netloc}"
                await self.emit_event(
                    url,
                    "URL_UNVERIFIED",
                    parent=parent_event,
                    tags=tags,
                    context=f"{{module}} probed {port_data} and detected a {protocol} web service",
                )
