import logging
import threading
from time import sleep

log = logging.getLogger("bbot.core.helpers.threadpool")

from .cache import CacheDict
from ...core.errors import ScanCancelledError


class ThreadPoolWrapper:
    """
    Layers more granular control overtop of a shared thread pool
    Allows setting lower thread limits for modules, etc.
    """

    def __init__(self, executor, max_workers=None):
        self.executor = executor
        self.max_workers = max_workers
        self.futures = set()
        self._future_lock = threading.Lock()
        self._submit_task_lock = threading.Lock()

    def submit_task(self, callback, *args, **kwargs):
        with self._submit_task_lock:
            if self.max_workers is not None:
                while self.num_tasks > self.max_workers:
                    sleep(0.1)
            try:
                future = self.executor.submit(callback, *args, **kwargs)
            except RuntimeError as e:
                raise ScanCancelledError(e)
        with self._future_lock:
            self.futures.add(future)
        return future

    @property
    def num_tasks(self):
        with self._future_lock:
            for f in list(self.futures):
                if f.done():
                    self.futures.remove(f)
            return len(self.futures) + (1 if self._submit_task_lock.locked() else 0)

    def shutdown(self, *args, **kwargs):
        self.executor.shutdown(*args, **kwargs)


def as_completed(fs):
    fs = list(fs)
    while fs:
        result = False
        for i, f in enumerate(fs):
            if f.done():
                result = True
                future = fs.pop(i)
                if future._state in ("CANCELLED", "CANCELLED_AND_NOTIFIED"):
                    continue
                yield future
                break
        if not result:
            sleep(0.05)


class _Lock:
    def __init__(self, name):
        self.name = name
        self.lock = threading.Lock()

    def __enter__(self):
        self.lock.acquire()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.lock.release()


class NamedLock:
    """
    Returns a unique threading.Lock() based on a provided string

    Useful for preventing multiple operations from occuring on the same data in parallel
    E.g. simultaneous DNS lookups on the same hostname
    """

    def __init__(self, max_size=1000):
        self._cache = CacheDict(max_size=max_size)

    def get_lock(self, name):
        try:
            return self._cache.get(name)
        except KeyError:
            new_lock = _Lock(name)
            self._cache.put(name, new_lock)
            return new_lock
