import shodan
from bbot.modules.base import BaseModule


class shodan_enterprise(BaseModule):
    watched_events = ["IP_ADDRESS"]
    produced_events = ["OPEN_TCP_PORT", "TECHNOLOGY", "OPEN_UDP_PORT", "ASN", "VULNERABILITY"]
    flags = ["passive"]
    meta = {
        "created_date": "2026-01-27",
        "author": "@Control-Punk-Delete",
        "description": "Shodan Enterprise API integration module.",
    }
    deps_pip = ["shodan"]
    options = {"api_key": None}
    options_desc = {"api_key": "Shodan API Key"}
    per_host_only = True
    scope_distance_modifier = 1
    target_only = True

    async def setup(self):
        if not self.config.get("api_key"):
            return None, "No API key specified"
        self.api_key = self.config.get("api_key")
        return True

    async def handle_event(self, event):
        try:
            api = shodan.Shodan(self.api_key)
            host = api.host(ips=event.data, history=False, minify=False)

            # ASN Extraction
            asn = {
                "asn": host["asn"][2:],
                "name": host["org"],
                "description": host["isp"],
                "country": host["country_code"],
            }

            await self.emit_event(
                asn,
                "ASN",
                parent=event,
                tags=host.get("tags"),
                context=f"Shodan API {event.data} request and find ASN",
            )

            if "data" in host:
                for data in host["data"]:
                    # TECHNOLOGY Extraction
                    ## TECHNOLOGY CPE Formats
                    if "cpe" in data:
                        for technology in data["cpe"]:
                            tech = {"technology": technology, "host": data.get("ip_str"), "port": data.get("port")}
                            await self.emit_event(
                                tech,
                                "TECHNOLOGY",
                                parent=event,
                                tags=data.get("tags") or [],
                                context=f"Shodan API {event.data} request and find TECHNOLOGY: {technology}",
                            )

                    if "cpe23" in data:
                        for technology in data["cpe23"]:
                            tech = {"technology": technology, "host": data.get("ip_str"), "port": data.get("port")}
                            await self.emit_event(
                                tech,
                                "TECHNOLOGY",
                                parent=event,
                                tags=data.get("tags") or [],
                                context=f"Shodan API {event.data} request and find TECHNOLOGY: {technology}",
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
                            context=f"Shodan API {event.data} request and find TECHNOLOGY: {data['product']}",
                        )

                    if "http" in data:
                        if "components" in data["http"]:
                            for technology in data["http"]["components"]:
                                tech = {"technology": technology, "host": data.get("ip_str"), "port": data.get("port")}
                                tags = data["http"]["components"][technology]["categories"]
                                tags.append("web-technology")
                                await self.emit_event(
                                    tech,
                                    "TECHNOLOGY",
                                    parent=event,
                                    tags=tags or [],
                                    context=f"Shodan API {event.data} request and find TECHNOLOGY: {technology}",
                                )

                    # OPEN_TCP_PORT, OPEN_UDP_PORT Extraction
                    if "port" in data and "transport" in data:
                        if data["transport"] == "tcp":
                            await self.emit_event(
                                self.helpers.make_netloc(event.data, data.get("port")),
                                "OPEN_TCP_PORT",
                                parent=event,
                                tags=data.get("tags") or [],
                                context=f"Shodan API {event.data} request and find TECHNOLOGY: {data.get('port')}",
                            )

                        elif data["transport"] == "udp":
                            await self.emit_event(
                                self.helpers.make_netloc(event.data, data.get("port")),
                                "OPEN_UDP_PORT",
                                parent=event,
                                tags=data.get("tags") or [],
                                context=f"Shodan API {event.data} request and find TECHNOLOGY: {data.get('port')}",
                            )

                        else:
                            self.warning(f"[WARNING] unknown transport {data['transport']}")

                    # VULNERABILITY Extraction
                    # NIST cvss score severity mapping
                    severity_map = {"NONE": 0.0, "LOW": 0.1, "MEDIUM": 4.0, "HIGH": 7.0, "CRITICAL": 9.0}

                    if "vulns" in data:
                        for item in data["vulns"]:
                            cve = item
                            vuln = {
                                "host": data.get("ip_str"),
                                "severity": max(
                                    (
                                        level
                                        for level, threshold in severity_map.items()
                                        if data["vulns"][item].get("cvss") >= threshold
                                    ),
                                    key=lambda x: severity_map[x],
                                ),
                                "description": f"{cve}",
                            }

                            await self.emit_event(
                                vuln,
                                "VULNERABILITY",
                                parent=event,
                                tags=[],
                                context=f"Shodan API {event.data} request and find VULNERABILITY {cve}",
                            )

            else:
                self.warning(f"No Shodan data about {event.data}")

        except shodan.APIError as e:
            self.error(f"Shodan API error: {e}")
