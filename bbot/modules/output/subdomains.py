from contextlib import suppress

from bbot.modules.base import BaseModule
from bbot.modules.output.human import Human


class Subdomains(Human):
    watched_events = ["DNS_NAME", "DNS_NAME_UNRESOLVED"]
    flags = ["subdomain-enum"]
    meta = {"description": "Output only resolved, in-scope subdomains"}
    options = {"output_file": "", "include_unresolved": False}
    options_desc = {"output_file": "Output to file", "include_unresolved": "Include unresolved subdomains in output"}
    accept_dupes = False
    in_scope_only = True

    output_filename = "subdomains.txt"

    async def setup(self):
        self.include_unresolved = self.config.get("include_unresolved", False)
        return await super().setup()

    async def filter_event(self, event):
        if event.type == "DNS_NAME_UNRESOLVED" and not self.include_unresolved:
            return False, "Not accepting unresolved subdomain (include_unresolved=False)"
        return True

    def _scope_distance_check(self, event):
        return BaseModule._scope_distance_check(self, event)

    async def handle_event(self, event):
        if self.file is not None:
            self.file.write(f"{event.data}\n")
            self.file.flush()

    async def cleanup(self):
        if getattr(self, "_file", None) is not None:
            with suppress(Exception):
                self.file.close()

    async def report(self):
        if getattr(self, "_file", None) is not None:
            self.info(f"Saved subdomains to {self.output_file}")
