from nmappalyzer import NmapScan

from .base import BaseModule

class Nmap(BaseModule):

    watched_events = ['IPV4_ADDRESS', 'IPV6_ADDRESS', 'IPV4_RANGE', 'IPV6_RANGE', 'DOMAIN', 'SUBDOMAIN', 'OPEN_TCP_PORT']
    produced_events = ['OPEN_TCP_PORT', 'SERVICE']
    max_threads = 10
    batch_size = 10

    def handle_batch(self, *events):

        portscan = dict()
        for event in events:

            if event.type in ['IPV4_ADDRESS', 'IPV6_ADDRESS', 'IPV4_RANGE', 'IPV6_RANGE', 'DOMAIN', 'SUBDOMAIN']:
                portscan[event.data] = event

            elif event.type in ['OPEN_TCP_PORT']:
                host,port = event.data.split(':')
                scan = NmapScan(host, ['-n', f'-p{port}', '-sV', '-Pn', '-T5', '--noninteractive'])
                for host in scan:
                    for portelem in host.etree.findall('ports/port'):
                        for service in portelem.findall('service'):
                            servicename = service.attrib.get('name', '')
                            if servicename:
                                self.emit_event(f'{host.address}:{port}:{servicename}', 'SERVICE', event)

        if portscan:
            scan = NmapScan(list(portscan), ['-n', '-Pn', '--top-ports', '100', '-T5', '--noninteractive'])
            for host in scan:
                for i in [host.address] + list(host.hostnames):
                    source_event = portscan.get(i, None)
                    if source_event:
                        break

                for open_port in host.open_ports:
                    port, protocol = open_port.split('/')
                    if protocol.lower() == 'tcp':
                        self.emit_event(f'{host.address}:{port}', 'OPEN_TCP_PORT', source_event)

    def finish(self):
        self.success('Nmap finished')