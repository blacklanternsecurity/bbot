from .base import BaseModule
from urllib.parse import urlparse


class header_brute(BaseModule):

    watched_events = ["URL"]
    produced_events = ["VULNERABILITY"]
    flags = ["brute_force"]
    options = {"header_wordlist": "https://raw.githubusercontent.com/PortSwigger/param-miner/master/resources/headers"}
    options_desc = {"header_wordlist": "Define the wordlist to be used to derive headers"}
    scanned_hosts = []
    header_blacklist = ["content-length", "expect", "transfer-encoding"]
    max_threads = 12

    def setup(self):

        self.wordlist = self.helpers.download(self.config.get("header_wordlist"), cache_hrs=720)
        return True

    def handle_event(self, event):

        parsed_host = urlparse(event.data)
        host = f"{parsed_host.scheme}://{parsed_host.netloc}/"

        if host in self.scanned_hosts:
            self.debug(f"Host {host} was already scanned, exiting")
        else:
            self.scanned_hosts.append(host)

        baseline = self.helpers.request(host)
        baseline_check = self.helpers.request(host)
        c = self.compare_request(baseline, baseline_check)

        if c == False:
            self.debug("Failed baseline check (response is dynamic without altering input), aborting")
            return

        futures = {}

        with open(self.wordlist, errors="ignore") as f:
            for header in f:
                if "%" not in header:
                    header = header.rstrip()
                    if header not in self.header_blacklist:
                        future = self.submit_task(self.check_header, baseline, host, header)
                        futures[future] = header

            for future in self.helpers.as_completed(futures):
                header = futures[future]
                result = future.result()
                if result == False:
                    self.emit_event(f"[HEADER_BRUTEFORCE] Host: {host} Header: {header}", "VULNERABILITY", event)

    def compare_request(self, baseline, test_request):

        # compare status_code
        if baseline.status_code != baseline.status_code:
            return False
        # compare text
        if baseline.text != test_request.text:
            return False
        return True

    def check_header(self, baseline, host, header):

        rand = self.helpers.rand_string()
        test_header = {header: rand}
        test_request = self.helpers.request(host, headers=test_header)
        return self.compare_request(baseline, test_request)
