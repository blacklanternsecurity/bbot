import random
from contextlib import suppress
from queue import PriorityQueue, Empty


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
        except Exception:
            return e


class EventQueue(PriorityQueue):
    """
    A "meta-queue" class that includes five queues, one for each priority

    Events are taken from the queues in a weighted random fashion based
    on the priority of their parent module.

    This prevents complete exclusion of lower-priority events

    This queue also tracks events by module and event type for stat purposes
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.event_types = dict()
        self.modules = dict()
        self._queues = dict()
        self._priorities = (1, 2, 3, 4, 5)
        self._weights = (10, 7, 5, 3, 1)
        for priority in self._priorities:
            q = PriorityQueue(*args, **kwargs)
            self._queues[priority] = q

    @property
    def events(self):
        for q in self._queues:
            for e in q.queue:
                yield e.event

    def _qsize(self):
        return sum(q._qsize() for q in self._queues.values())

    def empty(self):
        return all(q.empty() for q in self._queues.values())

    def _put(self, item):
        queued_event = QueuedEvent(item)
        q = self._queues[queued_event.event.module_priority]
        self._increment(self.event_types, queued_event.event.type)
        self._increment(self.modules, str(queued_event.event.module))
        q._put(queued_event)

    def _get(self):
        # first pick a (weighted) random queue
        priority = self._random_priority()
        try:
            # and get an event from it
            queued_event = self._queues[priority]._get()
        # if that fails
        except IndexError:
            # try every queue
            queues = [_ for _ in self._queues.values() if not _.empty()]
            if not queues:
                raise Empty
            queued_event = queues[0]._get()
        self._decrement(self.event_types, queued_event.event.type)
        self._decrement(self.modules, str(queued_event.event.module))
        return queued_event.item

    def _random_priority(self):
        return random.choices(self._priorities, weights=self._weights, k=1)[0]

    def _increment(self, d, v):
        try:
            d[v] += 1
        except KeyError:
            d[v] = 1

    def _decrement(self, d, v):
        with suppress(KeyError):
            d[v] = max(0, d[v] - 1)
