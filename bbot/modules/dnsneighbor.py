import ipaddress

from .base import BaseModule


class dnsneighbor(BaseModule):

    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum"]
    in_scope_only = True
    options = {"num_bits": 4}
    options_desc = {"num_bits": "Netmask size (in CIDR notation) to check. Default is 4 bits (16 hosts)"}

    def setup(self):
        self.processed = set()
        self.num_bits = max(1, int(self.config.get("num_bits", 4)))
        return True

    def handle_event(self, event):
        ips_to_check = set()
        ips = []
        for i in self.helpers.resolve(event.data):
            if self.helpers.is_ip(i):
                ips.append(ipaddress.ip_address(i))
        for ip in ips:
            netmask = ip.max_prefixlen - min(ip.max_prefixlen, self.num_bits)
            network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
            for ip in network:
                ip_hash = hash(ip)
                if ip_hash not in self.processed:
                    self.processed.add(ip_hash)
                    ips_to_check.add(str(ip))
        if ips_to_check:
            # emit IP neighbors
            for ip in ips_to_check:
                self.emit_event(ip, "IP_ADDRESS", event, internal=True)
            # try to resolve IP neighbors
            self.debug(f"Checking {len(ips_to_check):,} IPs")
            for query, results in self.helpers.dns.resolve_batch(ips_to_check):
                results = list(results)
                for result in results:
                    if not self.helpers.is_ip(result):
                        self.emit_event(result, "DNS_NAME", event, abort_if_not_tagged="in_scope")
