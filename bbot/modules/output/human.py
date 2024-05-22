from contextlib import suppress

from bbot.core.helpers.logger import log_to_stderr
from bbot.modules.output.base import BaseOutputModule


class Human(BaseOutputModule):
    watched_events = ["*"]
    meta = {"description": "Output to text", "created_date": "2022-04-07", "author": "@TheTechromancer"}
    options = {"output_file": "", "console": True}
    options_desc = {"output_file": "Output to file", "console": "Output to console"}
    vuln_severity_map = {"LOW": "HUGEWARNING", "MEDIUM": "HUGEWARNING", "HIGH": "CRITICAL", "CRITICAL": "CRITICAL"}
    accept_dupes = False

    output_filename = "output.txt"

    async def setup(self):
        self._prep_output_dir(self.output_filename)
        return True

    async def handle_event(self, event):
        event_type = f"[{event.type}]"
        event_tags = ""
        if getattr(event, "tags", []):
            event_tags = f'\t({", ".join(sorted(getattr(event, "tags", [])))})'
        event_str = f"{event_type:<20}\t{event.data_human}\t{event.module_sequence}{event_tags}"
        # log vulnerabilities in vivid colors
        if event.type == "VULNERABILITY":
            severity = event.data.get("severity", "INFO")
            if severity in self.vuln_severity_map:
                loglevel = self.vuln_severity_map[severity]
                log_to_stderr(event_str, level=loglevel, logname=False)
        elif event.type == "FINDING":
            log_to_stderr(event_str, level="HUGEINFO", logname=False)

        if self.file is not None:
            self.file.write(event_str + "\n")
            self.file.flush()
        if self.config.get("console", True):
            self.stdout(event_str)

    async def cleanup(self):
        if getattr(self, "_file", None) is not None:
            with suppress(Exception):
                self.file.close()

    async def report(self):
        if getattr(self, "_file", None) is not None:
            self.info(f"Saved TXT output to {self.output_file}")
