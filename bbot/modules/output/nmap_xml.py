import sys
from xml.dom import minidom
from datetime import datetime
from xml.etree.ElementTree import Element, SubElement, tostring

from bbot import __version__
from bbot.modules.output.base import BaseOutputModule


class NmapHost:
    __slots__ = ["hostnames", "open_ports"]

    def __init__(self):
        self.hostnames = set()
        # a dict of {port: {protocol: banner}}
        self.open_ports = dict()


class Nmap_XML(BaseOutputModule):
    watched_events = ["OPEN_TCP_PORT", "DNS_NAME", "IP_ADDRESS", "PROTOCOL", "HTTP_RESPONSE"]
    meta = {"description": "Output to Nmap XML", "created_date": "2024-11-16", "author": "@TheTechromancer"}
    output_filename = "output.nmap.xml"
    in_scope_only = True

    async def setup(self):
        self.hosts = {}
        self._prep_output_dir(self.output_filename)
        return True

    async def handle_event(self, event):
        event_host = event.host

        # we always record by IP
        ips = []
        for ip in event.resolved_hosts:
            try:
                ips.append(self.helpers.make_ip_type(ip))
            except ValueError:
                continue
        if not ips and self.helpers.is_ip(event_host):
            ips = [event_host]

        for ip in ips:
            try:
                nmap_host = self.hosts[ip]
            except KeyError:
                nmap_host = NmapHost()
                self.hosts[ip] = nmap_host

            event_port = getattr(event, "port", None)
            if event.type == "OPEN_TCP_PORT":
                if event_port not in nmap_host.open_ports:
                    nmap_host.open_ports[event.port] = {}
            elif event.type in ("PROTOCOL", "HTTP_RESPONSE"):
                if event_port is not None:
                    try:
                        existing_services = nmap_host.open_ports[event.port]
                    except KeyError:
                        existing_services = {}
                        nmap_host.open_ports[event.port] = existing_services
                    if event.type == "PROTOCOL":
                        protocol = event.data["protocol"].lower()
                        banner = event.data.get("banner", None)
                    elif event.type == "HTTP_RESPONSE":
                        protocol = event.parsed_url.scheme.lower()
                        banner = event.http_title
                    if protocol not in existing_services:
                        existing_services[protocol] = banner

            if self.helpers.is_ip(event_host):
                if str(event.module) == "PTR":
                    nmap_host.hostnames.add(event.parent.data)
            else:
                nmap_host.hostnames.add(event_host)

    async def report(self):
        scan_start_time = str(int(self.scan.start_time.timestamp()))
        scan_start_time_str = self.scan.start_time.strftime("%a %b %d %H:%M:%S %Y")
        scan_end_time = datetime.now()
        scan_end_time_str = scan_end_time.strftime("%a %b %d %H:%M:%S %Y")
        scan_end_time_timestamp = str(scan_end_time.timestamp())
        scan_duration = scan_end_time - self.scan.start_time
        num_hosts_up = len(self.hosts)

        # Create the root element
        nmaprun = Element(
            "nmaprun",
            {
                "scanner": "bbot",
                "args": " ".join(sys.argv),
                "start": scan_start_time,
                "startstr": scan_start_time_str,
                "version": str(__version__),
                "xmloutputversion": "1.05",
            },
        )

        ports_scanned = []
        speculate_module = self.scan.modules.get("speculate", None)
        if speculate_module is not None:
            ports_scanned = speculate_module.ports
        portscan_module = self.scan.modules.get("portscan", None)
        if portscan_module is not None:
            ports_scanned = self.helpers.parse_port_string(str(portscan_module.ports))
        num_ports_scanned = len(sorted(ports_scanned))
        ports_scanned = ",".join(str(x) for x in sorted(ports_scanned))

        # Add scaninfo
        SubElement(
            nmaprun,
            "scaninfo",
            {"type": "syn", "protocol": "tcp", "numservices": str(num_ports_scanned), "services": ports_scanned},
        )

        # Add host information
        for ip, nmap_host in self.hosts.items():
            hostnames = sorted(nmap_host.hostnames)
            ports = sorted(nmap_host.open_ports)

            host_elem = SubElement(nmaprun, "host")
            SubElement(host_elem, "status", {"state": "up", "reason": "user-set", "reason_ttl": "0"})
            SubElement(host_elem, "address", {"addr": str(ip), "addrtype": f"ipv{ip.version}"})

            if hostnames:
                hostnames_elem = SubElement(host_elem, "hostnames")
                for hostname in hostnames:
                    SubElement(hostnames_elem, "hostname", {"name": hostname, "type": "user"})

            ports = SubElement(host_elem, "ports")
            for port, protocols in nmap_host.open_ports.items():
                port_elem = SubElement(ports, "port", {"protocol": "tcp", "portid": str(port)})
                SubElement(port_elem, "state", {"state": "open", "reason": "syn-ack", "reason_ttl": "0"})
                # <port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="53"/><service name="http" product="AkamaiGHost" extrainfo="Akamai&apos;s HTTP Acceleration/Mirror service" tunnel="ssl" method="probed" conf="10"/></port>
                for protocol, banner in protocols.items():
                    attrs = {"name": protocol, "method": "probed", "conf": "10"}
                    if banner is not None:
                        attrs["product"] = banner
                        attrs["extrainfo"] = banner
                    SubElement(port_elem, "service", attrs)

        # Add runstats
        runstats = SubElement(nmaprun, "runstats")
        SubElement(
            runstats,
            "finished",
            {
                "time": scan_end_time_timestamp,
                "timestr": scan_end_time_str,
                "summary": f"BBOT done at {scan_end_time_str}; {num_hosts_up} scanned in {scan_duration} seconds",
                "elapsed": str(scan_duration.total_seconds()),
                "exit": "success",
            },
        )
        SubElement(runstats, "hosts", {"up": str(num_hosts_up), "down": "0", "total": str(num_hosts_up)})

        # make backup of the file
        self.helpers.backup_file(self.output_file)

        # Pretty-format the XML
        rough_string = tostring(nmaprun, encoding="utf-8")
        reparsed = minidom.parseString(rough_string)

        # Create a new document with the doctype
        doctype = minidom.DocumentType("nmaprun")
        reparsed.insertBefore(doctype, reparsed.documentElement)

        pretty_xml = reparsed.toprettyxml(indent="  ")

        with open(self.output_file, "w") as f:
            f.write(pretty_xml)
        self.info(f"Saved Nmap XML output to {self.output_file}")
