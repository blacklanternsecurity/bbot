from .base import BaseOutputModule


class Human(BaseOutputModule):
    def handle_event(self, event):
        event_type = f"[{event.type}]"
        event_tags = ""
        event.tags.add(f"distance: {event.scope_distance}")
        if event.tags:
            event_tags = f'\t({", ".join(getattr(event, "tags", []))})'
        self.stdout(f"{event_type:<20}\t{event.data}\t{event.module}{event_tags}")
