from .base import BaseModule
from urllib.parse import urlparse


class vhost(BaseModule):

    scanned_hosts = []
    watched_events = ["URL"]
    produced_events = ["URL"]
    special_vhost_list = ["127.0.0.1", "localhost", "host.docker.internal"]
    options = {
        "subdomain_wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
        "force_basehost": "",
    }
    options_desc = {"subdomain_wordlist": "Wordlist containing subdomains"}

    def handle_event(self, event):
        if not self.helpers.is_ip(event.host) or self.config.get("force_basehost"):

            subdomain_wordlist = self.helpers.download(self.config.get("subdomain_wordlist"), cache_hrs=720)
            parsed_host = urlparse(event.data)
            host = f"{parsed_host.scheme}://{parsed_host.netloc}/"

            if host in self.scanned_hosts:
                self.debug(f"Host {host} was already scanned, exiting")
                return
            else:
                self.scanned_hosts.append(host)

            # subdomain vhost check
            self.debug("Main vhost bruteforce")
            self.debug(self.config.get("force_basehost"))
            if self.config.get("force_basehost"):
                basehostraw = self.config.get("force_basehost")
            else:
                basehostraw = ".".join(parsed_host.netloc.split(".")[-2:])

            self.debug(f"Basehost: {basehostraw}")
            basehost = f".{basehostraw}"
            command = ["ffuf", "-ac", "-s", "-w", subdomain_wordlist, "-u", host, "-H", f"Host: FUZZ{basehost}"]
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
            vhost_dict = {"host": host, "vhost": found_vhost}
            if f"{vhost_dict['vhost']}{basehost}" != parsed_host.netloc:
                self.emit_event(vhost_dict, "VHOST", source=event, tags=["vhost"])
                if skip_dns_host == False:
                    self.emit_event(f"{vhost_dict['vhost']}{basehost}", "DNS_HOST", source=event, tags=["vhost"])
                yield vhost_dict["vhost"]

    def mutations_check(self, vhost):
        mutations_list = []
        for mutation in self.helpers.word_cloud.mutations(vhost):
            for i in ["", ".", "-"]:
                mutations_list.append(i.join(mutation))
        mutations_list_file = self.helpers.tempfile(mutations_list)
        return mutations_list_file
