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
            filename.parent.mkdir(exist_ok=True, parents=True)
            self.file = open(str(filename), mode="w")
        return True

    def handle_event(self, event):
        event_dict = dict(event)
        source_id = getattr(self.get_event_source(event), "id", "")
        event_dict["source"] = source_id
        event_str = json.dumps(event_dict)
        if self.file is not None:
            self.file.write(event_str + "\n")
            self.file.flush()
        else:
            self.stdout(event_str)

    def cleanup(self):
        if self.output_file:
            self.file.close()

    def get_event_source(self, event):
        if event.source._omit:
            return self.get_event_source(event.source)
        return event.source
