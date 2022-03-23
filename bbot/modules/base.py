import queue
import logging
import threading
from time import sleep
from contextlib import suppress

from bbot.core.event import make_event


class BaseModule:

    # Event types to watch
    watched_events = []
    # Event types to produce
    produced_events = []
    # Options, e.g. {"api_key": ""}
    options = {}
    # Options description, e.g. {"api_key": "API Key"}
    options_desc = {}
    # Maximum threads (how many instances of handle_event() can be running at once)
    max_threads = 1
    # Batch size
    # If batch size > 1, override handle_batch() instead of handle_event()
    batch_size = 1
    # Seconds to wait before force-submitting batch
    batch_wait = 10
    # Priority, smaller numbers run first
    _priority = 0
    # Name, overridden automatically in __init__.py
    _name = "base"

    def __init__(self, scan):
        self.scan = scan
        self.errored = False
        self._log = None
        self._event_queue = None
        self._batch_idle = 0

    def setup(self):
        """
        Optionally override this method.
        """
        pass

    def handle_event(self, event):
        """
        Override this method if batch_size == 1.
        """
        pass

    def handle_batch(self, *events):
        """
        Override this method if batch_size > 1.
        """
        pass

    def _handle_batch(self, force=False):
        if self.num_queued_events > 0 and (
            force or self.num_queued_events >= self.batch_size
        ):
            self._batch_idle = 0
            self.debug(
                f'Handling batch of {self.num_queued_events:,} events for module "{self.name}"'
            )
            events = list(self.events_waiting)
            if events:
                self.pool_execute(self.handle_batch, *events)

    def emit_event(self, *args, **kwargs):
        kwargs['module'] = self.name
        event = make_event(*args, **kwargs)
        self.log.debug(f'module "{self.name}" raised {event}')
        self.scan.manager.queue_event(event)

    @property
    def events_waiting(self):
        """
        yields all events in queue, up to maximum batch size
        """
        left = int(self.batch_size)
        while left > 0:
            try:
                event = self.event_queue.get_nowait()
                if type(event) == str and event == "FINISHED":
                    self.finish()
                else:
                    left -= 1
                    yield event
            except queue.Empty:
                break

    @property
    def num_queued_events(self):
        if self.event_queue:
            return self.event_queue.qsize()
        return 0

    @property
    def num_queued_tasks(self):
        return self.scan.shared_thread_pool.num_queued_tasks(
            f"{self.name}_threadworker"
        ) + self.scan.shared_thread_pool.num_running_tasks(f"{self.name}_threadworker")

    def start(self):
        self.thread = threading.Thread(target=self._worker)
        self.thread.start()

    def finish(self):
        """
        Perform final functions when scan is nearing completion
        Note that this function may be called multiple times
        Optionally override this method.
        """
        return

    def _worker(self):
        # keep track of how long we've been running
        iterations = 0
        try:
            while not self.scan.stopping:

                iterations += 1
                if self.batch_size > 1:
                    if iterations % 3 == 0:
                        self._batch_idle += 1
                    force = self._batch_idle >= self.batch_wait
                    self._handle_batch(force=force)

                else:
                    try:
                        if self.event_queue:
                            e = self.event_queue.get_nowait()
                        else:
                            self.debug(
                                f'Event queue for module "{self.name}" is in bad state'
                            )
                    except queue.Empty:
                        sleep(0.3333)
                        continue
                    self.debug(f"{self.name}._worker() got {e.__repr__()}")
                    # if we receive the special "FINISHED" event
                    if type(e) == str and e == "FINISHED":
                        self._handle_batch(force=True)
                        self.pool_execute(self.finish)
                    else:
                        self.pool_execute(self.handle_event, e)

        except KeyboardInterrupt:
            self.debug(f"Interrupted module {self.name}")
            self.scan.stop()
        except Exception as e:
            import traceback

            self.error(
                f"Exception ({e.__class__.__name__}) in module {self.name}:\n{traceback.format_exc()}"
            )
            self.set_error_state()

    def queue_event(self, e):
        if self.event_queue is not None and not self.errored:
            if (
                type(e) == str
                and e == "FINISHED"
                or any(
                    t in self.watched_events for t in ["*", getattr(e, "type", None)]
                )
            ):
                self.event_queue.put(e)
        else:
            self.log.debug(
                f"Module {self.name} is not in an acceptable state to queue event"
            )

    def pool_execute(self, callback, *args, **kwargs):
        """
        Execute a callback within the shared thread pool.
        """
        self.scan.shared_thread_pool.submit(
            callback,
            *args,
            task_name=f"{self.name}_threadworker",
            max_threads=self.max_threads,
            **kwargs,
        )

    def set_error_state(self):
        if not self.errored:
            self.debug(f"Setting error state for module {self.name}")
            self.errored = True
            # clear incoming queue
            if self.event_queue:
                self.debug(f"Emptying {self.name}.event_queue")
                with suppress(queue.Empty):
                    while 1:
                        self.event_queue.get_nowait()
                # set queue to None to prevent its use
                # if there are leftover objects in the queue, the scan will hang.
                self._event_queue = False

    @property
    def name(self):
        return str(self._name)

    @property
    def helpers(self):
        return self.scan.helpers

    @property
    def running(self):
        """
        Indicates whether the module is currently processing data.
        """
        running = (self.num_queued_tasks + self.num_queued_events) > 0
        return running

    @property
    def config(self):
        return self.scan.config.get("modules", {}).get(self.name, {})

    @property
    def event_queue(self):
        if self._event_queue is None:
            self._event_queue = queue.Queue()
        return self._event_queue

    @property
    def log(self):
        if self._log is None:
            self._log = logging.getLogger(f"bbot.agent.modules.{self.name}")
        return self._log

    def debug(self, *args, **kwargs):
        self.log.debug(*args, extra={"scan_id": self.scan.id}, **kwargs)

    def verbose(self, *args, **kwargs):
        self.log.verbose(*args, extra={"scan_id": self.scan.id}, **kwargs)

    def info(self, *args, **kwargs):
        self.log.info(*args, extra={"scan_id": self.scan.id}, **kwargs)

    def success(self, *args, **kwargs):
        self.log.success(*args, extra={"scan_id": self.scan.id}, **kwargs)

    def warning(self, *args, **kwargs):
        self.log.warning(*args, extra={"scan_id": self.scan.id}, **kwargs)

    def error(self, *args, **kwargs):
        self.log.error(*args, extra={"scan_id": self.scan.id}, **kwargs)

    def critical(self, *args, **kwargs):
        self.log.critical(*args, extra={"scan_id": self.scan.id}, **kwargs)
