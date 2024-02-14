import uuid
import random
import asyncio
import logging
import threading
from datetime import datetime
from queue import Queue, Empty
from cachetools import LRUCache
from .misc import human_timedelta
from contextlib import asynccontextmanager

log = logging.getLogger("bbot.core.helpers.async_helpers")


class ShuffleQueue(asyncio.Queue):
    def _put(self, item):
        random_index = random.randint(0, self.qsize())
        self._queue.insert(random_index, item)

    def _get(self):
        return self._queue.popleft()


class _Lock(asyncio.Lock):
    def __init__(self, name):
        self.name = name
        super().__init__()


class NamedLock:
    """
    Returns a unique asyncio.Lock() based on a provided string

    Useful for preventing multiple operations from occurring on the same data in parallel
    E.g. simultaneous DNS lookups on the same hostname
    """

    def __init__(self, max_size=1000):
        self._cache = LRUCache(maxsize=max_size)

    @asynccontextmanager
    async def lock(self, name):
        try:
            lock = self._cache[name]
        except KeyError:
            lock = _Lock(name)
            self._cache[name] = lock
        async with lock:
            yield


class TaskCounter:
    def __init__(self):
        self.tasks = {}
        self.lock = asyncio.Lock()  # create a new lock

    @property
    def value(self):
        return sum([t.n for t in self.tasks.values()])

    def count(self, task_name, n=1, _log=True):
        if callable(task_name):
            task_name = f"{task_name.__qualname__}()"
        return self.Task(self, task_name, n=n, _log=_log)

    class Task:
        def __init__(self, manager, task_name, n=1, _log=True):
            self.manager = manager
            self.task_name = task_name
            self.task_id = None
            self.start_time = None
            self.log = _log
            self.n = n

        async def __aenter__(self):
            self.task_id = uuid.uuid4()
            # if self.log:
            #     log.trace(f"Starting task {self.task_name} ({self.task_id})")
            async with self.manager.lock:
                self.start_time = datetime.now()
                self.manager.tasks[self.task_id] = self
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            async with self.manager.lock:
                self.manager.tasks.pop(self.task_id, None)
            # if self.log:
            #     log.trace(f"Finished task {self.task_name} ({self.task_id})")

        def __str__(self):
            running_for = human_timedelta(datetime.now() - self.start_time)
            return f"{self.task_name} running for {running_for}"


def async_to_sync_gen(async_gen):
    # Queue to hold generated values
    queue = Queue()

    # Flag to indicate if the async generator is done
    is_done = False

    # Function to run in the separate thread
    async def runner():
        nonlocal is_done
        try:
            async for value in async_gen:
                queue.put(value)
        finally:
            is_done = True

    def generator():
        while True:
            # Try to get a value from the queue
            try:
                yield queue.get(timeout=0.1)
            except Empty:
                # If the queue is empty, check if the async generator is done
                if is_done:
                    break

    # Start the event loop in a separate thread
    thread = threading.Thread(target=lambda: asyncio.run(runner()))
    thread.start()

    # Return the generator
    return generator()
