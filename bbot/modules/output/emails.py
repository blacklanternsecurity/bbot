from bbot.modules.base import BaseModule
from bbot.modules.output.human import Human


class Emails(Human):
    watched_events = ["EMAIL_ADDRESS"]
    flags = ["email-enum"]
    meta = {"description": "Output any email addresses found belonging to the target domain"}
    options = {"output_file": ""}
    options_desc = {"output_file": "Output to file"}
    in_scope_only = True

    output_filename = "emails.txt"

    async def setup(self):
        self.emails_written = 0
        return await super().setup()

    def _scope_distance_check(self, event):
        return BaseModule._scope_distance_check(self, event)

    async def handle_event(self, event):
        if self.file is not None:
            self.emails_written += 1
            self.file.write(f"{event.data}\n")
            self.file.flush()

    async def report(self):
        if getattr(self, "_file", None) is not None:
            self.info(f"Saved {self.emails_written:,} email addresses to {self.output_file}")
