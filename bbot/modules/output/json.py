import json
from pathlib import Path

from .base import BaseOutputModule


class JSON(BaseOutputModule):
    options = {"output_file": ""}
    options_desc = {"output_file": "Output to file"}

    def setup(self):
        self.output_file = self.config.get("output_file", "")
        self.file = None
        if self.output_file:
            filename = Path(self.output_file).resolve()
            self.helpers.mkdir(filename.parent)
            self.file = open(str(filename), mode="w")
        return True

    def handle_event(self, event):
        event_str = json.dumps(dict(event))
        if self.file is not None:
            self.file.write(event_str + "\n")
            self.file.flush()
        else:
            self.stdout(event_str)

    def cleanup(self):
        if self.output_file:
            self.file.close()
