from lxml import etree
from bbot.modules.base import BaseModule


class nmap(BaseModule):
    watched_events = ["IP_ADDRESS", "DNS_NAME"]
    produced_events = ["OPEN_TCP_PORT"]
    flags = ["active", "portscan", "aggressive", "web-thorough"]
    meta = {"description": "Execute port scans with nmap"}
    options = {
        "ports": "",
        "top_ports": 100,
        "timing": "T4",
        "skip_host_discovery": True,
    }
    options_desc = {
        "ports": "ports to scan",
        "top_ports": "top ports to scan",
        "timing": "-T<0-5>: Set timing template (higher is faster)",
        "skip_host_discovery": "skip host discovery (-Pn)",
    }
    max_event_handlers = 2
    batch_size = 256
    _priority = 2

    deps_apt = ["nmap"]
    deps_pip = ["lxml~=4.9.2"]

    async def setup(self):
        self.helpers.depsinstaller.ensure_root(message="Nmap requires root privileges")
        self.ports = self.config.get("ports", "")
        self.timing = self.config.get("timing", "T4")
        self.top_ports = self.config.get("top_ports", 100)
        self.skip_host_discovery = self.config.get("skip_host_discovery", True)
        return True

    async def handle_batch(self, *events):
        target = self.helpers.make_target(events)
        targets = list(set(str(e.data) for e in events))
        command, output_file = self.construct_command(targets)
        try:
            await self.helpers.run(command, sudo=True)
            for host in self.parse_nmap_xml(output_file):
                source_event = None
                for h in [host.address] + host.hostnames:
                    source_event = target.get(h)
                    if source_event is not None:
                        break
                if source_event is None:
                    self.warning(f"Failed to correlate source event from {host}")
                    source_event = self.scan.root_event
                for port in host.open_ports:
                    port_number = int(port.split("/")[0])
                    netloc = self.helpers.make_netloc(host.address, port_number)
                    self.emit_event(netloc, "OPEN_TCP_PORT", source=source_event)
                    for hostname in host.hostnames:
                        netloc = self.helpers.make_netloc(hostname, port_number)
                        self.emit_event(netloc, "OPEN_TCP_PORT", source=source_event)
        finally:
            output_file.unlink(missing_ok=True)

    def construct_command(self, targets):
        ports = self.config.get("ports", "")
        top_ports = self.config.get("top_ports", "")
        temp_filename = self.helpers.temp_filename(extension="xml")
        command = [
            "nmap",
            "-n",
            f"-{self.timing}",
            "-oX",
            temp_filename,
        ]
        if self.skip_host_discovery:
            command += ["-Pn"]
        if ports:
            command += ["-p", ports]
        else:
            command += ["--top-ports", top_ports]
        command += targets
        return command, temp_filename

    def parse_nmap_xml(self, xml_file):
        try:
            with open(xml_file, "rb") as f:
                et = etree.parse(f)
                for host in et.iter("host"):
                    yield NmapHost(host)
        except Exception as e:
            self.warning(f"Error parsing Nmap XML at {xml_file}: {e}")

    async def cleanup(self):
        resume_file = self.helpers.current_dir / "resume.cfg"
        resume_file.unlink(missing_ok=True)


class NmapHost(str):
    def __init__(self, xml):
        self.etree = xml

        # convenient host information
        self.status = self.etree.find("status").attrib.get("state", "down")
        self.address = self.etree.find("address").attrib.get("addr", "")
        self.hostnames = []
        for hostname in self.etree.findall("hostnames/hostname"):
            hostname = hostname.attrib.get("name")
            if hostname and not hostname in self.hostnames:
                self.hostnames.append(hostname)

        # convenient port information
        self.scripts = dict()
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        for port in self.etree.findall("ports/port"):
            port_name = port.attrib.get("portid", "0") + "/" + port.attrib.get("protocol", "tcp").lower()
            port_status = port.find("state").attrib.get("state", "closed")
            if port_status in ("open", "closed", "filtered"):
                getattr(self, f"{port_status}_ports").append(port_name)
            for script in port.iter("script"):
                script_name = script.attrib.get("id", "")
                script_output = script.attrib.get("output", "")
                if script_name:
                    try:
                        self.scripts[port_name][script_name] = script_output
                    except KeyError:
                        self.scripts[port_name] = {script_name: script_output}

    def __str__(self):
        address = self.address + (" " if self.address else "")
        hostnames = "(" + ", ".join(self.hostnames) + ")" if self.hostnames else ""
        return f"{address}{hostnames}"

    def __repr__(self):
        return str(self)
