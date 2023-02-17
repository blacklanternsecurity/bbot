import logging
import threading
import traceback
from datetime import datetime
from queue import SimpleQueue, Full
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger("bbot.core.helpers.threadpool")

from .cache import CacheDict
from ...core.errors import ScanCancelledError


def pretty_fn(a):
    if callable(a):
        return a.__qualname__
    return a


class ThreadPoolSimpleQueue(SimpleQueue):
    def __init__(self, *args, **kwargs):
        self._executor = kwargs.pop("_executor", None)

    def get(self, *args, **kwargs):
        work_item = super().get(*args, **kwargs)
        thread_id = threading.get_ident()
        self._executor._current_work_items[thread_id] = (work_item, datetime.now())
        return work_item


class BBOTThreadPoolExecutor(ThreadPoolExecutor):
    """
    Allows inspection of thread pool to determine which functions are currently executing
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._current_work_items = {}
        self._work_queue = ThreadPoolSimpleQueue(_executor=self)

    @property
    def threads_status(self):
        work_items = []
        for thread_id, (work_item, start_time) in sorted(self._current_work_items.items()):
            func = work_item.fn.__qualname__
            func_index = 0
            if work_item and not work_item.future.done():
                for i, f in enumerate(list(work_item.args)):
                    if callable(f):
                        func = f.__qualname__
                        func_index = i + 1
                    else:
                        break
                running_for = datetime.now() - start_time
                wi_args = list(work_item.args)[func_index:]
                wi_args = [pretty_fn(a) for a in wi_args]
                wi_args = str(wi_args).strip("[]")
                wi_kwargs = ", ".join(["{0}={1}".format(k, pretty_fn(v)) for k, v in work_item.kwargs.items()])
                func_with_args = f"{func}({wi_args}" + (f", {wi_kwargs}" if wi_kwargs else "") + ")"
                work_items.append(
                    (running_for, f"running for {int(running_for.total_seconds()):>3} seconds: {func_with_args}")
                )
        work_items.sort(key=lambda x: x[0])
        return [x[-1] for x in work_items]


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

        self._num_tasks = 0
        self._task_count_lock = threading.Lock()

        self._lock = threading.RLock()
        self.not_full = threading.Condition(self._lock)

    def submit_task(self, callback, *args, **kwargs):
        """
        A wrapper around threadpool.submit()
        """
        block = kwargs.get("_block", True)
        force = kwargs.get("_force_submit", False)
        success = False
        with self.not_full:
            self.num_tasks_increment()
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
                    future = self.executor.submit(self._execute_callback, callback, *args, **kwargs)
                    future.add_done_callback(self._on_future_done)
                    success = True
                    return future
                except RuntimeError as e:
                    raise ScanCancelledError(e)
            finally:
                if not success:
                    self.num_tasks_decrement()

    def _execute_callback(self, callback, *args, **kwargs):
        try:
            return callback(*args, **kwargs)
        finally:
            self.num_tasks_decrement()

    def _on_future_done(self, future):
        if future.cancelled():
            self.num_tasks_decrement()

    @property
    def num_tasks(self):
        with self._task_count_lock:
            return self._num_tasks

    def num_tasks_increment(self):
        with self._task_count_lock:
            self._num_tasks += 1

    def num_tasks_decrement(self):
        with self._task_count_lock:
            self._num_tasks = max(0, self._num_tasks - 1)
        for wrapper in self.executor._thread_pool_wrappers:
            try:
                with wrapper.not_full:
                    wrapper.not_full.notify()
            except RuntimeError:
                continue
            except Exception as e:
                log.warning(f"Unknown error in num_tasks_decrement(): {e}")
                log.trace(traceback.format_exc())

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

    @property
    def threads_status(self):
        return self.executor.threads_status


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
