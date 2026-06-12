from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class shodan_enterprise(BaseModule):
    watched_events = ["IP_ADDRESS"]
    produced_events = ["OPEN_TCP_PORT", "TECHNOLOGY", "OPEN_UDP_PORT", "FINDING"]
    flags = ["safe", "passive"]
    meta = {
        "created_date": "2026-01-27",
        "author": "@Control-Punk-Delete",
        "description": "Shodan Enterprise API integration module.",
    }

    class Config(BaseModuleConfig):
        api_key: str | list[str] = Field("", description="Shodan API Key", sensitive=True, mandatory=True)
        in_scope_only: bool = Field(
            True, description="Only query in-scope IPs. If False, will query up to distance 1."
        )

    in_scope_only = True

    base_url = "https://api.shodan.io"

    async def setup(self):
        self.api_key = self.config.get("api_key", "")
        if not self.api_key:
            return None, "No API key specified"
        if not self.config.get("in_scope_only", True):
            self.in_scope_only = False
            self.scope_distance_modifier = 1
            self.warning(
                "in_scope_only is disabled. This module queries each IP individually and may consume a lot of API credits!"
            )
        return True

    async def handle_event(self, event):
        ip = event.data
        url = f"{self.base_url}/shodan/host/{self.helpers.quote(ip)}?key={{api_key}}"
        r = await self.api_request(url)
        if r is None:
            self.warning(f"No response from Shodan API for {ip}")
            return
        status_code = getattr(r, "status_code", 0)
        if status_code == 404:
            self.warning(f"No Shodan data about {ip}")
            return
        if not getattr(r, "is_success", False):
            self.warning(f"Shodan API error for {ip} (status {status_code})")
            return
        try:
            host = r.json()
        except Exception as e:
            self.warning(f"Failed to parse Shodan API response for {ip}: {e}")
            return

        if "data" not in host:
            self.warning(f"No Shodan data about {ip}")
            return

        # NIST cvss score severity mapping
        severity_map = {"NONE": 0.0, "LOW": 0.1, "MEDIUM": 4.0, "HIGH": 7.0, "CRITICAL": 9.0}

        for data in host["data"]:
            # TECHNOLOGY Extraction
            ## TECHNOLOGY CPE Formats
            for technology in data.get("cpe", []):
                tech = {"technology": technology, "host": data.get("ip_str"), "port": data.get("port")}
                await self.emit_event(
                    tech,
                    "TECHNOLOGY",
                    parent=event,
                    tags=data.get("tags") or [],
                    context=f"{{module}} queried Shodan API for {ip} and found TECHNOLOGY: {technology}",
                )

            for technology in data.get("cpe23", []):
                tech = {"technology": technology, "host": data.get("ip_str"), "port": data.get("port")}
                await self.emit_event(
                    tech,
                    "TECHNOLOGY",
                    parent=event,
                    tags=data.get("tags") or [],
                    context=f"{{module}} queried Shodan API for {ip} and found TECHNOLOGY: {technology}",
                )

            # TECHNOLOGY Additional Formats
            if "product" in data:
                tech = {
                    "technology": data.get("product"),
                    "host": data.get("ip_str"),
                    "port": data.get("port"),
                }
                await self.emit_event(
                    tech,
                    "TECHNOLOGY",
                    parent=event,
                    tags=data.get("tags") or [],
                    context=f"{{module}} queried Shodan API for {ip} and found TECHNOLOGY: {data['product']}",
                )

            if "http" in data:
                if "components" in data["http"]:
                    for technology in data["http"]["components"]:
                        tech = {"technology": technology, "host": data.get("ip_str"), "port": data.get("port")}
                        tags = list(data["http"]["components"][technology].get("categories", []))
                        tags.append("web-technology")
                        await self.emit_event(
                            tech,
                            "TECHNOLOGY",
                            parent=event,
                            tags=tags,
                            context=f"{{module}} queried Shodan API for {ip} and found TECHNOLOGY: {technology}",
                        )

            # OPEN_TCP_PORT, OPEN_UDP_PORT Extraction
            if "port" in data and "transport" in data:
                if data["transport"] == "tcp":
                    await self.emit_event(
                        self.helpers.make_netloc(ip, data.get("port")),
                        "OPEN_TCP_PORT",
                        parent=event,
                        tags=data.get("tags") or [],
                        context=f"{{module}} queried Shodan API for {ip} and found OPEN_TCP_PORT: {data.get('port')}",
                    )
                elif data["transport"] == "udp":
                    await self.emit_event(
                        self.helpers.make_netloc(ip, data.get("port")),
                        "OPEN_UDP_PORT",
                        parent=event,
                        tags=data.get("tags") or [],
                        context=f"{{module}} queried Shodan API for {ip} and found OPEN_UDP_PORT: {data.get('port')}",
                    )
                else:
                    self.warning(f"Unknown transport {data['transport']}")

            # FINDING Extraction
            if "vulns" in data:
                for cve, vuln_data in data["vulns"].items():
                    cvss = vuln_data.get("cvss", 0)
                    severity = max(
                        (level for level, threshold in severity_map.items() if cvss >= threshold),
                        key=lambda x: severity_map[x],
                    )
                    vuln = {
                        "name": "Shodan - Possible Vulnerabilities",
                        "host": data.get("ip_str"),
                        "severity": severity,
                        "description": cve,
                        "confidence": "LOW",
                    }
                    await self.emit_event(
                        vuln,
                        "FINDING",
                        parent=event,
                        tags=[],
                        context=f"{{module}} queried Shodan API for {ip} and found FINDING {cve}",
                    )
