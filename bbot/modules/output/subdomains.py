from bbot.modules.output.txt import TXT
from bbot.modules.base import BaseModule


class Subdomains(TXT):
    watched_events = ["DNS_NAME", "DNS_NAME_UNRESOLVED"]
    flags = ["subdomain-enum"]
    meta = {
        "description": "Output only resolved, in-scope subdomains",
        "created_date": "2023-07-31",
        "author": "@TheTechromancer",
    }
    options = {"output_file": "", "include_unresolved": False}
    options_desc = {"output_file": "Output to file", "include_unresolved": "Include unresolved subdomains in output"}
    accept_dupes = False
    in_scope_only = True

    output_filename = "subdomains.txt"

    async def setup(self):
        self.include_unresolved = self.config.get("include_unresolved", False)
        self.subdomains_written = 0
        return await super().setup()

    async def filter_event(self, event):
        if event.type == "DNS_NAME_UNRESOLVED" and not self.include_unresolved:
            return False, "Not accepting unresolved subdomain (include_unresolved=False)"
        return True

    def _scope_distance_check(self, event):
        return BaseModule._scope_distance_check(self, event)

    async def handle_event(self, event):
        if self.file is not None:
            self.subdomains_written += 1
            self.file.write(f"{event.data}\n")
            self.file.flush()

    async def report(self):
        if getattr(self, "_file", None) is not None:
            self.info(f"Saved {self.subdomains_written:,} subdomains to {self.output_file}")
