from bbot.modules.base import BaseModule


class burpsuite(BaseModule):
    watched_events = ["DNS_NAME", "URL", "URL_UNVERIFIED"]
    produced_events = ["SITEMAP"]
    flags = ["passive", "safe"]

    meta = {
        "description": "BurpSuite extenion to populate the sitemap feature with found URLs and endpoints.",
        "created_date": "2024-08-03",
        "author": "@jackpas23",
    }
    options = {
        "proxyaddr": "127.0.0.1",
        "proxyport": "8080",
        "requesttag": "X-BBOT-Identifier: bbot generated request",
    }

    options_desc = {
        "proxyaddr": "Specify specfic proxy address, default is Burpsuite(127.0.0.1)",
        "proxyport": "Specify specfic proxy port, default is Burpsuite(8080)",
        "requesttag": "Request identifier to find bbot generated findings",
    }

    deps_apt = ["proxychains4"]

    # one-time setup - runs at the beginning of the scan
    async def setup(self):
        config = (
            "dynamic_chain\n"
            "proxy_dns\n"
            "remote_dns_subnet 224\n"
            "tcp_read_time_out 15000\n"
            "tcp_connect_time_out 8000\n"
            "[ProxyList]\n"
            f"http\t{self.options['proxyaddr']}\t{self.options['proxyport']}"
        )
        print(f"Proxy configuration: {config}")
        f = open("proxychains.conf", "w")
        f.write(config)
        f.close
        return True

    async def handle_event(self, event):
        self.hugesuccess(f"Got {event} (event.data: {event.data})")
        # option to enforce TLS?
        url = f"https://{event.host}"
        # print(f"{event.host}")
        print(self.options["proxyaddr"])
        command = [
            "proxychains",
            "-f",
            "proxychains.conf",
            "curl",
            "-H",
            self.options["requesttag"],
            "--max-time",
            "3",
            url,
        ]
        self.hugeinfo("Running proxychains with curl command...")
        result = await self.run_process(command)
        self.hugeinfo(f"{result}")
        return True
