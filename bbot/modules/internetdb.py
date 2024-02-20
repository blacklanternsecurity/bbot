from bbot.modules.base import BaseModule


class internetdb(BaseModule):
    """
    Query IP in Shodan InternetDB, returning open ports, discovered technologies, and findings/vulnerabilities
    API reference: https://internetdb.shodan.io/docs

    Example API response:

    {
        "cpes": [
            "cpe:/a:microsoft:internet_information_services",
            "cpe:/a:microsoft:outlook_web_access:15.0.1367",
        ],
        "hostnames": [
            "autodiscover.evilcorp.com",
            "mail.evilcorp.com",
        ],
        "ip": "1.2.3.4",
        "ports": [
            25,
            80,
            443,
        ],
        "tags": [
            "starttls",
            "self-signed",
            "eol-os"
        ],
        "vulns": [
            "CVE-2021-26857",
            "CVE-2021-26855"
        ]
    }
    """

    watched_events = ["IP_ADDRESS", "DNS_NAME"]
    produced_events = ["TECHNOLOGY", "VULNERABILITY", "FINDING", "OPEN_TCP_PORT", "DNS_NAME"]
    flags = ["passive", "safe", "portscan", "subdomain-enum"]
    meta = {"description": "Query Shodan's InternetDB for open ports, hostnames, technologies, and vulnerabilities"}

    _qsize = 500

    base_url = "https://internetdb.shodan.io"

    async def setup(self):
        self.processed = set()
        return True

    async def filter_event(self, event):
        ip = self.get_ip(event)
        if ip:
            ip_hash = hash(ip)
            if ip_hash in self.processed:
                return False, "IP was already processed"
            self.processed.add(ip_hash)
            return True
        return False, "event had no valid IP addresses"

    async def handle_event(self, event):
        ip = self.get_ip(event)
        if ip is None:
            return
        url = f"{self.base_url}/{ip}"
        r = await self.request_with_fail_count(url)
        if r is None:
            self.debug(f"No response for {event.data}")
            return
        try:
            data = r.json()
        except Exception as e:
            self.verbose(f"Error parsing JSON response from {url}: {e}")
            self.trace()
            return
        if data:
            if r.status_code == 200:
                await self._parse_response(data=data, event=event)
            elif r.status_code == 404:
                detail = data.get("detail", "")
                if detail:
                    self.debug(f"404 response for {url}: {detail}")
            else:
                err_data = data.get("type", "")
                err_msg = data.get("msg", "")
                self.verbose(f"Shodan error for {ip}: {err_data}: {err_msg}")

    async def _parse_response(self, data: dict, event):
        """Handles emitting events from returned JSON"""
        data: dict  # has keys: cpes, hostnames, ip, ports, tags, vulns
        # ip is a string, ports is a list of ports, the rest is a list of strings
        for hostname in data.get("hostnames", []):
            await self.emit_event(hostname, "DNS_NAME", source=event)
        for cpe in data.get("cpes", []):
            await self.emit_event({"technology": cpe, "host": str(event.host)}, "TECHNOLOGY", source=event)
        for port in data.get("ports", []):
            await self.emit_event(
                self.helpers.make_netloc(event.data, port), "OPEN_TCP_PORT", source=event, internal=True, quick=True
            )
        vulns = data.get("vulns", [])
        if vulns:
            vulns_str = ", ".join([str(v) for v in vulns])
            await self.emit_event(
                {"description": f"Shodan reported verified vulnerabilities: {vulns_str}", "host": str(event.host)},
                "FINDING",
                source=event,
            )

    def get_ip(self, event):
        """
        Get the first available IP address from an event (IP_ADDRESS or DNS_NAME)
        """
        if event.type == "IP_ADDRESS":
            return event.host
        elif event.type == "DNS_NAME":
            # always try IPv4 first
            ipv6 = []
            ips = [h for h in event.resolved_hosts if self.helpers.is_ip(h)]
            for ip in sorted([str(ip) for ip in ips]):
                if self.helpers.is_ip(ip, version=4):
                    return ip
                elif self.helpers.is_ip(ip, version=6):
                    ipv6.append(ip)
            for ip in ipv6:
                return ip
