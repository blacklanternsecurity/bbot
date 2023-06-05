import asyncio
import logging
import threading
from queue import Queue, Empty
from contextlib import asynccontextmanager

log = logging.getLogger("bbot.core.helpers.async_helpers")

from .cache import CacheDict


class _Lock(asyncio.Lock):
    def __init__(self, name):
        self.name = name
        super().__init__()


class NamedLock:
    """
    Returns a unique asyncio.Lock() based on a provided string

    Useful for preventing multiple operations from occuring on the same data in parallel
    E.g. simultaneous DNS lookups on the same hostname
    """

    def __init__(self, max_size=1000):
        self._cache = CacheDict(max_size=max_size)

    @asynccontextmanager
    async def lock(self, name):
        try:
            lock = self._cache.get(name)
        except KeyError:
            lock = _Lock(name)
            self._cache.put(name, lock)
        async with lock:
            yield


class TaskCounter:
    def __init__(self):
        self.value = 0

    def __enter__(self):
        self.value += 1

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.value -= 1


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
