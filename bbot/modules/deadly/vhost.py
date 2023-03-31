from bbot.modules.base import BaseModule
from bbot.modules.deadly.wfuzz import wfuzz

from urllib.parse import urlparse
import json
import random
import string


class vhost(wfuzz):
    watched_events = ["URL"]
    produced_events = ["VHOST", "DNS_NAME"]
    flags = ["active", "aggressive", "slow"]
    meta = {"description": "Fuzz for virtual hosts"}

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

    deps_pip = ["wfuzz"]

    in_scope_only = True

    def setup(self):
        self.canary = "".join(random.choice(string.ascii_lowercase) for i in range(10))
        self.scanned_hosts = {}
        self.wordlist = self.helpers.wordlist(self.config.get("wordlist"))
        f = open(self.wordlist, "r")
        self.wordlist_lines = f.readlines()
        f.close()
        self.ignore_redirects = True
        self.tempfile, tempfile_len = self.generate_templist()
        return True

    @staticmethod
    def get_parent_domain(domain):
        domain_parts = domain.split(".")

        if len(domain_parts) >= 3:
            parent_domain = ".".join(domain_parts[1:])
            return parent_domain
        else:
            return domain


    def handle_event(self, event):
        if not self.helpers.is_ip(event.host) or self.config.get("force_basehost"):
            host = f"{event.parsed.scheme}://{event.parsed.netloc}"
            if host in self.scanned_hosts.keys():
                return
            else:
                self.scanned_hosts[host] = event

            # subdomain vhost check
            self.verbose("Main vhost bruteforce")
            if self.config.get("force_basehost"):
                basehost = self.config.get("force_basehost")
            else:
                basehost = self.get_parent_domain(event.parsed.netloc)

            self.debug(f"Using basehost: {basehost}")
            for vhost in self.wfuzz_vhost(host, f".{basehost}", event):
                self.verbose(f"Starting mutations check for {vhost}")
                for vhost in self.wfuzz_vhost(host, f".{basehost}", event, wordlist=self.mutations_check(vhost)):
                    pass

            # check existing host for mutations
            self.verbose("Checking for vhost mutations on main host")
            for vhost in self.wfuzz_vhost(host, f".{basehost}", event, wordlist=self.mutations_check(event.parsed.netloc.split(".")[0])):
                pass

            # special vhost list
            self.verbose("Checking special vhost list")
            for vhost in self.wfuzz_vhost(host, "", event, wordlist=self.helpers.tempfile(self.special_vhost_list,pipe=False), skip_dns_host=True):
                pass

    def wfuzz_vhost(self, host, basehost, event, wordlist=None, skip_dns_host=False):
        filters = self.baseline_wfuzz(f"{host}/", exts=[""], prefix="", suffix=basehost, mode="hostheader")
        self.debug(f"Baseline completed and returned these filters:")
        self.debug(filters)
        if not wordlist:
            wordlist = self.tempfile
        for r in self.execute_wfuzz(wordlist, host, exts=[""], suffix=basehost, filters=filters, mode="hostheader"):
            found_vhost = r["payload"]
            vhost_dict = {"host": str(event.host), "url": host, "vhost": found_vhost}
            if f"{vhost_dict['vhost']}{basehost}" != event.parsed.netloc:
                self.emit_event(vhost_dict, "VHOST", source=event)
                if skip_dns_host == False:
                    self.emit_event(f"{vhost_dict['vhost']}{basehost}", "DNS_NAME", source=event, tags=["vhost"])

                yield vhost_dict["vhost"]

    def mutations_check(self, vhost):
        mutations_list = []
        for mutation in self.helpers.word_cloud.mutations(vhost):
            for i in ["", ".", "-"]:
                mutations_list.append(i.join(mutation))
        mutations_list_file = self.helpers.tempfile(mutations_list,pipe=False)
        return mutations_list_file

    def finish(self):
        # check existing hosts with wordcloud
        tempfile = self.helpers.tempfile(list(self.helpers.word_cloud.keys()), pipe=False)

        for host, event in self.scanned_hosts.items():
            event.parsed = urlparse(host)
            
            self.verbose("Checking main host with wordcloud")
            if self.config.get("force_basehost"):
                basehost = self.config.get("force_basehost")
            else:
                basehost = self.get_parent_domain(event.parsed.netloc)
 
            for vhost in self.wfuzz_vhost(host, f".{basehost}", event, wordlist=tempfile):
                pass
