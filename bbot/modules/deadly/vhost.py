from bbot.modules.base import BaseModule


class vhost(BaseModule):
    watched_events = ["URL"]
    produced_events = ["VHOST", "DNS_NAME"]
    flags = ["active", "brute-force", "aggressive", "slow", "web-advanced"]
    meta = {"description": "Fuzz for virtual hosts"}

    special_vhost_list = ["127.0.0.1", "localhost", "host.docker.internal"]
    options = {
        "subdomain_wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
        "force_basehost": "",
    }
    options_desc = {
        "subdomain_wordlist": "Wordlist containing subdomains",
        "force_basehost": "Use a custom base host (e.g. evilcorp.com) instead of the default behavior of using the current URL",
    }
    deps_ansible = [
        {
            "name": "Download ffuf",
            "unarchive": {
                "src": "https://github.com/ffuf/ffuf/releases/download/v#{BBOT_MODULES_FFUF_VERSION}/ffuf_#{BBOT_MODULES_FFUF_VERSION}_#{BBOT_OS}_#{BBOT_CPU_ARCH}.tar.gz",
                "include": "ffuf",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        }
    ]
    in_scope_only = True

    def setup(self):
        self.scanned_hosts = set()
        self.subdomain_wordlist = self.helpers.wordlist(self.config.get("subdomain_wordlist"))
        return True

    def handle_event(self, event):
        if not self.helpers.is_ip(event.host) or self.config.get("force_basehost"):
            parsed_host = event.parsed
            host = f"{parsed_host.scheme}://{parsed_host.netloc}/"
            host_hash = hash(host)
            if host_hash in self.scanned_hosts:
                self.debug(f"Host {host} was already scanned, exiting")
                return
            else:
                self.scanned_hosts.add(host_hash)

            # subdomain vhost check
            self.debug("Main vhost bruteforce")
            if self.config.get("force_basehost"):
                basehostraw = self.config.get("force_basehost")
            else:
                basehostraw = self.helpers.parent_domain(event.host)

            self.debug(f"Basehost: {basehostraw}")
            basehost = f".{basehostraw}"
            command = ["ffuf", "-ac", "-s", "-w", self.subdomain_wordlist, "-u", host, "-H", f"Host: FUZZ{basehost}"]
            for vhost in self.ffuf_vhost(command, host, parsed_host, basehost, event):
                self.debug(f"Starting mutations check for {vhost}")
                mutations_list_file = self.mutations_check(vhost)
                command = ["ffuf", "-ac", "-s", "-w", mutations_list_file, "-u", host, "-H", f"Host: FUZZ{basehost}"]
                self.ffuf_vhost(command, host, parsed_host, event, basehost)

            # check existing host for mutations
            self.debug("Checking for vhost mutations on main host")
            mutations_list_file = self.mutations_check(parsed_host.netloc.split(".")[0])
            command = ["ffuf", "-ac", "-s", "-w", mutations_list_file, "-u", host, "-H", f"Host: FUZZ{basehost}"]
            self.ffuf_vhost(command, host, parsed_host, basehost, event)

            # special vhost list
            self.debug("Checking special vhost list")
            basehost = basehostraw
            special_vhost_list_file = self.helpers.tempfile(self.special_vhost_list)
            command = ["ffuf", "-ac", "-s", "-w", special_vhost_list_file, "-u", host, "-H", f"Host: FUZZ"]
            self.ffuf_vhost(command, host, parsed_host, basehost, event, skip_dns_host=True)

    def ffuf_vhost(self, command, host, parsed_host, basehost, event, skip_dns_host=False):
        for found_vhost in self.helpers.run_live(command):
            found_vhost = found_vhost.rstrip()
            vhost_dict = {"host": str(event.host), "url": host, "vhost": found_vhost}
            if f"{vhost_dict['vhost']}{basehost}" != parsed_host.netloc:
                self.emit_event(vhost_dict, "VHOST", source=event)
                if skip_dns_host == False:
                    self.emit_event(f"{vhost_dict['vhost']}{basehost}", "DNS_NAME", source=event, tags=["vhost"])
                yield vhost_dict["vhost"]

    def mutations_check(self, vhost):
        mutations_list = []
        for mutation in self.helpers.word_cloud.mutations(vhost):
            for i in ["", ".", "-"]:
                mutations_list.append(i.join(mutation))
        mutations_list_file = self.helpers.tempfile(mutations_list)
        return mutations_list_file
