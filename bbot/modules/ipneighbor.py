import ipaddress

from bbot.modules.base import BaseModule


class ipneighbor(BaseModule):
    watched_events = ["IP_ADDRESS"]
    produced_events = ["IP_ADDRESS"]
    flags = ["passive", "subdomain-enum", "aggressive"]
    meta = {"description": "Look beside IPs in their surrounding subnet"}
    options = {"num_bits": 4}
    options_desc = {"num_bits": "Netmask size (in CIDR notation) to check. Default is 4 bits (16 hosts)"}
    scope_distance_modifier = 1
    _scope_shepherding = False

    async def setup(self):
        self.processed = set()
        self.num_bits = max(1, int(self.config.get("num_bits", 4)))
        return True

    async def filter_event(self, event):
        return str(event.module) not in {"speculate", "ipneighbor"}

    async def handle_event(self, event):
        main_ip = event.host
        netmask = main_ip.max_prefixlen - min(main_ip.max_prefixlen, self.num_bits)
        network = ipaddress.ip_network(f"{main_ip}/{netmask}", strict=False)
        subnet_hash = hash(network)
        if subnet_hash not in self.processed:
            self.processed.add(subnet_hash)
            for ip in network:
                if ip != main_ip:
                    ip_event = self.make_event(str(ip), "IP_ADDRESS", event, internal=True)
                    # keep the scope distance low to give it one more hop for DNS resolution
                    # ip_event.scope_distance = max(1, event.scope_distance)
                    self.emit_event(ip_event)
