from .base import BaseModule
import ipaddress


class dnsresolve(BaseModule):

    watched_events = [
        "IPV4_ADDRESS",
        "IPV4_RANGE",
        "IPV6_ADDRESS",
        "IPV6_RANGE",
        "DNS_NAME",
    ]
    produced_events = ["IPV4_ADDRESS", "IPV6_ADDRESS", "DNS_NAME"]
    options = {"max_hosts": 65536}
    options_desc = {"max_hosts": "Define the max number of hosts a network range can contain"}

    def handle_event(self, event):
        if event.type == "DNS_NAME":

            self.debug(f"trying to resolve {event.data}")
            self.resolve_arr([event.data], event)

        else:
            net = ipaddress.ip_network(event.data)
            if (event.type == "IPV4_RANGE") or (event.type == "IPV6_RANGE"):
                config_max_hosts = self.config.get("max_hosts", 65536)
                if net.num_addresses > config_max_hosts:
                    self.debug(
                        f"dns resolve exceeded max host count ({config_max_hosts} hosts). Got a (/{net.prefixlen}) network with ({net.num_addresses:,}) hosts."
                    )
                    return
            self.resolve_arr(net, event)

    def resolve_arr(self, arr, event):
        futures = []
        for x in arr:
            future = self.helpers.submit_task(self.helpers.resolve, str(x))
            futures.append(future)
        for future in self.helpers.as_completed(futures):
            r_set = future.result()
            if r_set:
                self.emit_event(list(r_set)[0], source=event, tags=["resolved"])
