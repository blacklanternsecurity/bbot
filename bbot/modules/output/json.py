import json
from .base import BaseOutputModule


class JSON(BaseOutputModule):
    def handle_event(self, event):
        self.stdout(json.dumps(dict(event)))
