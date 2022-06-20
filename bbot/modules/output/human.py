from .base import BaseOutputModule


class Human(BaseOutputModule):
    def handle_event(self, event):
        event_type = f"[{event.type}]"
        event_tags = ""
        if getattr(event, "tags", []):
            event_tags = f'\t({", ".join(sorted(getattr(event, "tags", [])))})'
        self.stdout(f"{event_type:<20}\t{event.data}\t{event.module}{event_tags}")
