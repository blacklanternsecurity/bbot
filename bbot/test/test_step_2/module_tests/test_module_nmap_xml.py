import xml.etree.ElementTree as ET

from bbot.modules.base import BaseModule
from .base import ModuleTestBase


class TestNmap_XML(ModuleTestBase):
    modules_overrides = ["nmap_xml", "speculate"]
    targets = ["blacklanternsecurity.com", "127.0.0.3"]
    config_overrides = {"dns": {"minimal": False}}

    class DummyModule(BaseModule):
        watched_events = ["OPEN_TCP_PORT"]
        _name = "dummy_module"

        async def handle_event(self, event):
            if event.port == 80:
                await self.emit_event(
                    {"host": str(event.host), "port": event.port, "protocol": "http", "banner": "Apache"},
                    "PROTOCOL",
                    parent=event,
                )
            elif event.port == 443:
                await self.emit_event(
                    {"host": str(event.host), "port": event.port, "protocol": "https"}, "PROTOCOL", parent=event
                )

    async def setup_before_prep(self, module_test):
        self.dummy_module = self.DummyModule(module_test.scan)
        module_test.scan.modules["dummy_module"] = self.dummy_module
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["127.0.0.1", "127.0.0.2"]},
                "3.0.0.127.in-addr.arpa": {"PTR": ["www.blacklanternsecurity.com"]},
                "www.blacklanternsecurity.com": {"A": ["127.0.0.1"]},
            }
        )

    def check(self, module_test, events):
        nmap_xml_file = module_test.scan.modules["nmap_xml"].output_file
        nmap_xml = open(nmap_xml_file).read()

        # Parse the XML
        root = ET.fromstring(nmap_xml)

        # Expected IP addresses
        expected_ips = {"127.0.0.1", "127.0.0.2", "127.0.0.3"}
        found_ips = set()

        # Iterate over each host in the XML
        for host in root.findall("host"):
            # Get the IP address
            address = host.find("address").get("addr")
            found_ips.add(address)

            # Get hostnames if available
            hostnames = sorted([hostname.get("name") for hostname in host.findall(".//hostname")])

            # Get open ports and services
            ports = []
            for port in host.findall(".//port"):
                port_id = port.get("portid")
                state = port.find("state").get("state")
                if state == "open":
                    service_name = port.find("service").get("name")
                    service_product = port.find("service").get("product", "")
                    service_extrainfo = port.find("service").get("extrainfo", "")
                    ports.append((port_id, service_name, service_product, service_extrainfo))

            # Sort ports for consistency
            ports.sort()

            # Assertions
            if address == "127.0.0.1":
                assert hostnames == ["blacklanternsecurity.com", "www.blacklanternsecurity.com"]
                assert ports == sorted([("80", "http", "Apache", "Apache"), ("443", "https", "", "")])
            elif address == "127.0.0.2":
                assert hostnames == sorted(["blacklanternsecurity.com"])
                assert ports == sorted([("80", "http", "Apache", "Apache"), ("443", "https", "", "")])
            elif address == "127.0.0.3":
                assert hostnames == []  # No hostnames for this IP
                assert ports == sorted([("80", "http", "Apache", "Apache"), ("443", "https", "", "")])

        # Assert that all expected IPs were found
        assert found_ips == expected_ips
