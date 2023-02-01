import logging
import threading
from queue import Full

log = logging.getLogger("bbot.core.helpers.threadpool")

from .cache import CacheDict
from ...core.errors import ScanCancelledError


class ThreadPoolWrapper:
    """
    Layers more granular control overtop of a shared thread pool
    Allows setting lower thread limits for modules, etc.
    """

    def __init__(self, executor, max_workers=None, qsize=None):
        self.executor = executor
        self.max_workers = max_workers
        self.max_qsize = qsize
        self.futures = set()
        try:
            self.executor._thread_pool_wrappers.append(self)
        except AttributeError:
            self.executor._thread_pool_wrappers = [self]
        self.num_tasks = 0

        self._lock = threading.Lock()
        self.not_full = threading.Condition(self._lock)

    def submit_task(self, callback, *args, **kwargs):
        """
        A wrapper around threadpool.submit()
        """
        block = kwargs.get("_block", True)
        force = kwargs.get("_force_submit", False)
        success = False
        with self.not_full:
            self.num_tasks += 1
            try:
                if not force:
                    if not block:
                        if self.is_full or self.underlying_executor_is_full:
                            raise Full
                    else:
                        # wait until there's room
                        while self.is_full or self.underlying_executor_is_full:
                            self.not_full.wait()

                try:
                    # submit the job
                    future = self.executor.submit(self.callback_wrapper, callback, *args, **kwargs)
                    success = True
                except RuntimeError as e:
                    raise ScanCancelledError(e)
            finally:
                if not success:
                    self.num_tasks -= 1

            return future

    def callback_wrapper(self, callback, *args, **kwargs):
        try:
            return callback(*args, **kwargs)
        finally:
            self.num_tasks -= 1
            for wrapper in self.executor._thread_pool_wrappers:
                try:
                    with wrapper.not_full:
                        wrapper.not_full.notify()
                except RuntimeError:
                    continue

    @property
    def is_full(self):
        if self.max_workers is None:
            return False
        return self.num_tasks > self.max_workers

    @property
    def underlying_executor_is_full(self):
        return self.max_qsize is not None and self.qsize >= self.max_qsize

    @property
    def qsize(self):
        return self.executor._work_queue.qsize()

    def shutdown(self, *args, **kwargs):
        self.executor.shutdown(*args, **kwargs)


import time
from concurrent.futures._base import (
    FINISHED,
    _AS_COMPLETED,
    _AcquireFutures,
    _create_and_install_waiters,
    _yield_finished_futures,
)


def as_completed(fs, timeout=None):
    """
    Copied from https://github.com/python/cpython/blob/main/Lib/concurrent/futures/_base.py
    Modified to only yield FINISHED futures (not CANCELLED_AND_NOTIFIED)
    """
    if timeout is not None:
        end_time = timeout + time.monotonic()

    fs = set(fs)
    total_futures = len(fs)
    with _AcquireFutures(fs):
        finished = set(f for f in fs if f._state == FINISHED)
        pending = fs - finished
        waiter = _create_and_install_waiters(fs, _AS_COMPLETED)
    finished = list(finished)
    try:
        yield from _yield_finished_futures(finished, waiter, ref_collect=(fs,))

        while pending:
            if timeout is None:
                wait_timeout = None
            else:
                wait_timeout = end_time - time.monotonic()
                if wait_timeout < 0:
                    raise TimeoutError("%d (of %d) futures unfinished" % (len(pending), total_futures))

            waiter.event.wait(wait_timeout)

            with waiter.lock:
                finished = waiter.finished_futures
                waiter.finished_futures = []
                waiter.event.clear()

            # reverse to keep finishing order
            finished.reverse()
            yield from _yield_finished_futures(finished, waiter, ref_collect=(fs, pending))

    finally:
        # Remove waiter from unfinished futures
        for f in fs:
            with f._condition:
                f._waiters.remove(waiter)


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
