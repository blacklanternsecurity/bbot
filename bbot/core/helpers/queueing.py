from contextlib import suppress
from queue import PriorityQueue


class QueuedEvent(tuple):
    """
    Allows sorting of tuples in outgoing PriorityQueue
    """

    def __init__(self, item):
        self.item = item

    def __gt__(self, other):
        return self.event > other.event

    def __lt__(self, other):
        return self.event < other.event

    @property
    def event(self):
        return self._get_event(self.item)

    @staticmethod
    def _get_event(e):
        try:
            return e[0]
        except KeyError:
            return e


class EventQueue(PriorityQueue):
    def __init__(self, *args, **kwargs):
        self.event_types = dict()
        self.modules = dict()
        super().__init__(*args, **kwargs)

    @property
    def events(self):
        return [e.event for e in self.queue]

    def _put(self, item):
        queued_event = QueuedEvent(item)
        self._increment(self.event_types, queued_event.event.type)
        self._increment(self.modules, str(queued_event.event.module))
        super()._put(queued_event)

    def _get(self):
        queued_event = super()._get()
        self._decrement(self.event_types, queued_event.event.type)
        self._decrement(self.modules, str(queued_event.event.module))
        return queued_event.item

    def _increment(self, d, v):
        try:
            d[v] += 1
        except KeyError:
            d[v] = 1

    def _decrement(self, d, v):
        with suppress(KeyError):
            d[v] = max(0, d[v] - 1)
