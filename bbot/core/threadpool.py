import threading
from time import sleep

from ..core.errors import ScanCancelledError


class ThreadPoolWrapper:
    """
    Layers more granular control over a shared thread pool
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


@staticmethod
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
