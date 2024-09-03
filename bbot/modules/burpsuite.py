from bbot.modules.base import BaseModule

class burpsuite(BaseModule):
    watched_events = ["DNS_NAME","URL","URL_UNVERIFIED"] # watch for DNS_NAME events
    produced_events = ["SITEMAP"] # we produce WHOIS events
    flags = ["passive", "safe"]
    meta = {"description": "Extension to forward findings to burpsuite Sitemap"}
    deps_apt = ["proxychains4"]
    # one-time setup - runs at the beginning of the scan
    async def setup(self):
        config="dynamic_chain\nproxy_dns\nremote_dns_subnet 224\ntcp_read_time_out 15000\ntcp_connect_time_out 8000\n[ProxyList]\nhttp	127.0.0.1 8080"
        f = open("proxychains.conf","w")
        f.write(config)
        f.close
        return True

    async def handle_event(self, event):
        self.hugesuccess(f"Got {event} (event.data: {event.data})")
        _, domain = self.helpers.split_domain(event.data)

        #option to enforce TLS?
        url=f"https://{event.host}"
        print(f"{event.host}")
        command = ["proxychains", "-f", "proxychains.conf", "curl", "--max-time", "3", url]
        self.hugeinfo("Running proxychains with curl command...")
        result = await self.run_process(command)
        self.hugeinfo(f"{result}")
        return True