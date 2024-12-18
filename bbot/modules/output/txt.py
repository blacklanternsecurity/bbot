from contextlib import suppress

from bbot.modules.output.base import BaseOutputModule


class TXT(BaseOutputModule):
    watched_events = ["*"]
    meta = {"description": "Output to text", "created_date": "2024-04-03", "author": "@TheTechromancer"}
    options = {"output_file": ""}
    options_desc = {"output_file": "Output to file"}

    output_filename = "output.txt"

    async def setup(self):
        self._prep_output_dir(self.output_filename)
        return True

    async def handle_event(self, event):
        event_str = self.human_event_str(event)

        if self.file is not None:
            self.file.write(event_str + "\n")
            self.file.flush()

    async def cleanup(self):
        if getattr(self, "_file", None) is not None:
            with suppress(Exception):
                self.file.close()

    async def report(self):
        if getattr(self, "_file", None) is not None:
            self.info(f"Saved TXT output to {self.output_file}")
