import asyncio
import logging
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
