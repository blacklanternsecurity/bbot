import base64
from urllib.parse import urlparse

from bbot.modules.deadly.ffuf import ffuf


class vhost(ffuf):
    watched_events = ["URL"]
    produced_events = ["VHOST", "DNS_NAME"]
    flags = ["active", "aggressive", "slow"]
    meta = {"description": "Fuzz for virtual hosts", "created_date": "2022-05-02", "author": "@liquidsec"}

    special_vhost_list = ["127.0.0.1", "localhost", "host.docker.internal"]
    options = {
        "wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
        "force_basehost": "",
        "lines": 5000,
    }
    options_desc = {
        "wordlist": "Wordlist containing subdomains",
        "force_basehost": "Use a custom base host (e.g. evilcorp.com) instead of the default behavior of using the current URL",
        "lines": "take only the first N lines from the wordlist when finding directories",
    }

    deps_common = ["ffuf"]
    banned_characters = set([" ", "."])

    in_scope_only = True

    async def setup(self):
        self.scanned_hosts = {}
        self.wordcloud_tried_hosts = set()
        return await super().setup()

    async def handle_event(self, event):
        if not self.helpers.is_ip(event.host) or self.config.get("force_basehost"):
            host = f"{event.parsed_url.scheme}://{event.parsed_url.netloc}"
            if host in self.scanned_hosts.keys():
                return
            else:
                self.scanned_hosts[host] = event

            # subdomain vhost check
            self.verbose("Main vhost bruteforce")
            if self.config.get("force_basehost"):
                basehost = self.config.get("force_basehost")
            else:
                basehost = self.helpers.parent_domain(event.parsed_url.netloc)

            self.debug(f"Using basehost: {basehost}")
            async for vhost in self.ffuf_vhost(host, f".{basehost}", event):
                self.verbose(f"Starting mutations check for {vhost}")
                async for vhost in self.ffuf_vhost(host, f".{basehost}", event, wordlist=self.mutations_check(vhost)):
                    pass

            # check existing host for mutations
            self.verbose("Checking for vhost mutations on main host")
            async for vhost in self.ffuf_vhost(
                host, f".{basehost}", event, wordlist=self.mutations_check(event.parsed_url.netloc.split(".")[0])
            ):
                pass

            # special vhost list
            self.verbose("Checking special vhost list")
            async for vhost in self.ffuf_vhost(
                host,
                "",
                event,
                wordlist=self.helpers.tempfile(self.special_vhost_list, pipe=False),
                skip_dns_host=True,
            ):
                pass

    async def ffuf_vhost(self, host, basehost, event, wordlist=None, skip_dns_host=False):
        filters = await self.baseline_ffuf(f"{host}/", exts=[""], suffix=basehost, mode="hostheader")
        self.debug(f"Baseline completed and returned these filters:")
        self.debug(filters)
        if not wordlist:
            wordlist = self.tempfile
        async for r in self.execute_ffuf(
            wordlist, host, exts=[""], suffix=basehost, filters=filters, mode="hostheader"
        ):
            found_vhost_b64 = r["input"]["FUZZ"]
            vhost_str = base64.b64decode(found_vhost_b64).decode()
            vhost_dict = {"host": str(event.host), "url": host, "vhost": vhost_str}
            if f"{vhost_dict['vhost']}{basehost}" != event.parsed_url.netloc:
                await self.emit_event(
                    vhost_dict,
                    "VHOST",
                    parent=event,
                    context=f"{{module}} brute-forced virtual hosts for {event.data} and found {{event.type}}: {vhost_str}",
                )
                if skip_dns_host == False:
                    await self.emit_event(
                        f"{vhost_dict['vhost']}{basehost}",
                        "DNS_NAME",
                        parent=event,
                        tags=["vhost"],
                        context=f"{{module}} brute-forced virtual hosts for {event.data} and found {{event.type}}: {{event.data}}",
                    )

                yield vhost_dict["vhost"]

    def mutations_check(self, vhost):
        mutations_list = []
        for mutation in self.helpers.word_cloud.mutations(vhost):
            for i in ["", "-"]:
                mutations_list.append(i.join(mutation))
        mutations_list_file = self.helpers.tempfile(mutations_list, pipe=False)
        return mutations_list_file

    async def finish(self):
        # check existing hosts with wordcloud
        tempfile = self.helpers.tempfile(list(self.helpers.word_cloud.keys()), pipe=False)

        for host, event in self.scanned_hosts.items():
            if host not in self.wordcloud_tried_hosts:
                event.parsed_url = urlparse(host)

                self.verbose("Checking main host with wordcloud")
                if self.config.get("force_basehost"):
                    basehost = self.config.get("force_basehost")
                else:
                    basehost = self.helpers.parent_domain(event.parsed_url.netloc)

                async for vhost in self.ffuf_vhost(host, f".{basehost}", event, wordlist=tempfile):
                    pass

                self.wordcloud_tried_hosts.add(host)
