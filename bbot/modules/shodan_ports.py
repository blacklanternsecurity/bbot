from bbot.modules.base import BaseModule


class shodan_ports(BaseModule):
    """
    Query IP in Shodan, returning open ports, discovered technologies, and findings/vulnerabilities
    API reference: https://developer.shodan.io/api
    """

    watched_events = ["IP_ADDRESS"]
    produced_events = ["TECHNOLOGY", "VULNERABILITY", "FINDING", "OPEN_TCP_PORT", "DNS_NAME"]
    flags = ["passive", "safe", "portscan"]
    meta = {"description": "Query Shodan for open ports", "auth_required": True}
    options = {"api_key": ""}
    options_desc = {"api_key": "Shodan API key"}
    base_url = "https://api.shodan.io"
    scope_distance_modifier = 1

    @staticmethod
    def _severity_lookup(f: float) -> str:
        """
        Takes a CVSS v3 base score as input and returns the severity rating
        """
        if f >= 9.0:
            return "CRITICAL"
        elif 9.0 > f >= 7.0:
            return "HIGH"
        elif 7.0 > f >= 4.0:
            return "MEDIUM"
        elif 4.0 > f > 0:
            return "LOW"
        return "NONE"

    def _parse_response(self, data: dict, event):
        """Handles emiting events from returned JSON"""
        data: list[dict]
        found_domains: set[str] = set()
        # Decrease scope distance for ports since ports are directly connected to the host
        event.scope_distance = event.scope_distance - 1
        for datum in data:
            if port_number := datum.get("port"):
                netloc = self.helpers.make_netloc(event.data, port_number)
                # If TCP, report up
                if datum.get("transport") == "tcp":
                    self.emit_event(netloc, event_type="OPEN_TCP_PORT", source=event)
                # Check for vulns
                if vulns := datum.get("vulns"):
                    for cve, vuln_info in vulns.items():
                        vuln_data = {
                            "cve": cve,
                            "cvss": vuln_info.get("cvss", 0),
                            "host": str(event.host),
                            "netloc": netloc,
                            "verified": vuln_info.get("verified", False),
                            "description": "",
                            "port": port_number,
                            "severity": shodan_ports._severity_lookup(vuln_info["cvss"]),
                        }
                        if vuln_info["verified"]:
                            vuln_data["description"] = f"Shodan reported verified CVE {cve}"
                            self.emit_event(
                                vuln_data,
                                event_type="VULNERABILITY",
                                source=event,
                                severity=vuln_data["severity"],
                            )
                        else:
                            vuln_data["description"] = f"Shodan reported unverified CVE {cve}"
                            self.emit_event(
                                vuln_data,
                                event_type="FINDING",
                                source=event,
                            )

                # check for tech - os and cpe
                if os := datum.get("os"):
                    self.emit_event({"technology": os, "host": str(event.host), "type": "os"}, "TECHNOLOGY", event)
                if cpes := datum.get("cpe23"):
                    for cpe in cpes:
                        tech_data = {"technology": cpe, "host": str(event.host), "type": "cpe"}
                        self.emit_event(tech_data, "TECHNOLOGY", source=event)
                # check for domains
                if domains := datum.get("domains"):
                    for domain in domains:
                        found_domains.add(domain)
                if hostnames := datum.get("hostnames"):
                    for hostname in hostnames:
                        found_domains.add(hostname)
        for dns_name in found_domains:
            self.emit_event(dns_name, event_type="DNS_NAME", source=event)

    async def handle_event(self, event):
        url = f"{self.base_url}/shodan/host/{event.data}"
        r = await self.helpers.request(f"{url}?key={self.api_key}")
        if r is None:
            self.debug(f"No response for {event.data}")
            return
        try:
            json = r.json()
        except Exception:
            return
        if data := json.get("data"):
            # Iterate over each port. Inside the ports, we can get:
            # domains, hostnames, os, transport (tcp or udp), vulns
            self._parse_response(data=data, event=event)

    async def setup(self):
        await super().setup()
        return await self.require_api_key()
