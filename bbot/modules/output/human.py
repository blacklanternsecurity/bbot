from pathlib import Path

from bbot.modules.output.base import BaseOutputModule


class Human(BaseOutputModule):
    watched_events = ["*"]
    options = {"output_file": "", "console": True}
    options_desc = {"output_file": "Output to file", "console": "Output to console"}
    emit_graph_trail = False

    def setup(self):
        self.output_file = self.config.get("output_file", "")
        self.file = None
        if self.output_file:
            self.output_file = Path(self.output_file)
        else:
            self.output_file = self.scan.home / "output.txt"
        self.helpers.mkdir(self.output_file.parent)
        self.file = open(self.output_file, mode="w")
        return True

    def handle_event(self, event):
        event_type = f"[{event.type}]"
        event_tags = ""
        if getattr(event, "tags", []):
            event_tags = f'\t({", ".join(sorted(getattr(event, "tags", [])))})'
        event_str = f"{event_type:<20}\t{event.data_human}\t{event.module}{event_tags}"
        if self.file is not None:
            self.file.write(event_str + "\n")
            self.file.flush()
        if self.config.get("console", True):
            self.stdout(event_str)
