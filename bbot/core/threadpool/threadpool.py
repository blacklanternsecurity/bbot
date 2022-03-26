import queue
import logging
import threading
from time import sleep
from contextlib import suppress

from .worker import ThreadPoolWorker


class ThreadPool:
    def __init__(self, threads=100, qsize=10, name=None):

        if name is None:
            name = ""

        self.log = logging.getLogger(f"bbot.core.threadpool.{name}")
        self.numthreads = int(threads)
        self.qsize = int(qsize)
        self.pool = [None] * self.numthreads
        self.name = str(name)
        self.input_thread = None
        self.input_queues = dict()
        self.output_queues = dict()
        self._stop = False
        self._lock = threading.Lock()

    def start(self):
        self.log.debug(
            f'Starting thread pool "{self.name}" with {self.numthreads:,} threads'
        )
        for i in range(self.numthreads):
            t = ThreadPoolWorker(pool=self, name=f"{self.name}_worker_{i + 1}")
            t.start()
            self.pool[i] = t

    @property
    def stop(self):
        return self._stop

    @stop.setter
    def stop(self, val):
        assert val in (True, False), "stop must be either True or False"
        for t in self.pool:
            with suppress(Exception):
                t.stop = val
        self._stop = val

    def shutdown(self, wait=True):
        """Shut down the pool.

        Args:
            wait (bool): Whether to wait for the pool to finish executing

        Returns:
            results (dict): (unordered) results in the format: {'task_name': [returnvalue1, returnvalue2, ...]}
        """
        results = dict()
        self.log.debug(f'Shutting down thread pool "{self.name}" with wait={wait}')
        if wait:
            while not self.finished and not self.stop:
                with self._lock:
                    output_queues = list(self.output_queues)
                for task_name in output_queues:
                    moduleResults = list(self.results(task_name))
                    try:
                        results[task_name] += moduleResults
                    except KeyError:
                        results[task_name] = moduleResults
                sleep(0.1)
        self.stop = True
        # make sure input queues are empty
        with self._lock:
            input_queues = list(self.input_queues.values())
        for q in input_queues:
            with suppress(Exception):
                while 1:
                    q.get_nowait()
            with suppress(Exception):
                q.close()
        # make sure output queues are empty
        with self._lock:
            output_queues = list(self.output_queues.items())
        for task_name, q in output_queues:
            moduleResults = list(self.results(task_name))
            try:
                results[task_name] += moduleResults
            except KeyError:
                results[task_name] = moduleResults
            with suppress(Exception):
                q.close()
        return results

    def submit(self, callback, *args, **kwargs):
        """
        Submit a callback to the pool.
        The 'task_name' and 'max_threads' arguments are optional.
        """
        task_name = kwargs.get("task_name", "default")
        max_threads = kwargs.pop("max_threads", 100)
        # block if this module's thread limit has been reached
        while self.num_total_tasks(task_name) >= max_threads:
            sleep(0.01)
            continue
        self.log.debug(
            f'Submitting function "{callback.__name__}" from module "{task_name}"'
        )
        self.input_queue(task_name).put((callback, args, kwargs))

    def num_queued_tasks(self, task_name):
        queuedTasks = 0
        with suppress(Exception):
            queuedTasks += self.input_queues[task_name].qsize()
        return queuedTasks

    def num_running_tasks(self, task_name):
        runningTasks = 0
        for t in self.pool:
            with suppress(Exception):
                if t.task_name == task_name:
                    runningTasks += 1
        return runningTasks

    def num_total_tasks(self, task_name):
        return self.num_running_tasks(task_name) + self.num_queued_tasks(task_name)

    def input_queue(self, task_name="default"):
        try:
            return self.input_queues[task_name]
        except KeyError:
            self.input_queues[task_name] = queue.Queue(self.qsize)
            return self.input_queues[task_name]

    def output_queue(self, task_name="default"):
        try:
            return self.output_queues[task_name]
        except KeyError:
            self.output_queues[task_name] = queue.Queue(self.qsize)
            return self.output_queues[task_name]

    def map(self, callback, iterable, *args, **kwargs):  # noqa: A003
        """
        Args:
            iterable: each entry will be passed as the first argument to the function
            callback: the function to thread
            args: additional arguments to pass to callback function
            kwargs: keyword arguments to pass to callback function

        Yields:
            return values from completed callback function
        """
        task_name = kwargs.get("task_name", "default")
        self.input_thread = threading.Thread(
            target=self.feed_queue, args=(callback, iterable, args, kwargs)
        )
        self.input_thread.start()
        self.start()
        sleep(0.1)
        yield from self.results(task_name, wait=True)

    def results(self, task_name="default", wait=False):
        while 1:
            result = False
            with suppress(Exception):
                while 1:
                    yield self.output_queue(task_name).get_nowait()
                    result = True
            if not wait or self.num_total_tasks(task_name) == 0:
                break
            if not result:
                # sleep briefly to save CPU
                sleep(0.1)

    def feed_queue(self, callback, iterable, args, kwargs):
        for i in iterable:
            if self.stop:
                break
            self.submit(callback, i, *args, **kwargs)

    @property
    def finished(self):
        if self.stop:
            return True
        else:
            finishedThreads = [not t.busy for t in self.pool if t is not None]
            try:
                input_threadAlive = self.input_thread.is_alive()
            except AttributeError:
                input_threadAlive = False
            input_queuesEmpty = [q.empty() for q in self.input_queues.values()]
            return (
                not input_threadAlive
                and all(input_queuesEmpty)
                and all(finishedThreads)
            )

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.shutdown()
