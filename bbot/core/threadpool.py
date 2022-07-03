import logging
import threading
from time import sleep

log = logging.getLogger("bbot.core.threadpool")

from ..core.errors import ScanCancelledError


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
                    sleep(0.05)
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
    def __init__(self, parent, name):
        self.parent = parent
        self.name = name
        self.lock = threading.Lock()

    def __enter__(self):
        self.lock.acquire()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.lock.release()
        self.parent.remove_lock(self.name)


class NamedLock:
    """
    Returns a unique threading.Lock() based on a provided string

    Useful for preventing multiple operations from occuring on the same data in parallel
    E.g. simultaneous DNS lookups on the same hostname
    """

    def __init__(self):
        self._locks = {}
        self._main_lock = threading.Lock()

    def get_lock(self, name):
        with self._main_lock:
            try:
                return self._locks[hash(name)]
            except KeyError:
                new_lock = _Lock(self, name)
                self._locks[hash(name)] = new_lock
                return new_lock

    def remove_lock(self, name):
        with self._main_lock:
            try:
                lock = self._locks[hash(name)].lock
            except KeyError:
                return
            if lock.acquire(blocking=False):
                try:
                    del self._locks[hash(name)]
                except KeyError:
                    pass
                finally:
                    lock.release()
