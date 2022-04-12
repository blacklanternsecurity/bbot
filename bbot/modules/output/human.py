from .base import BaseOutputModule


class Human(BaseOutputModule):
    def handle_event(self, event):
        event_type = f"[{event.type}]"
        self.stdout(f"{event_type:<20}{event.data}")
