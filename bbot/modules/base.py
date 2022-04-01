import queue
import logging
import threading
import traceback
from time import sleep
from contextlib import suppress

from bbot.core.event import make_event


class BaseModule:

    # Event types to watch
    watched_events = []
    # Event types to produce
    produced_events = []
    # Flags
    flags = []
    # Whether to accept duplicate events
    accept_dupes = False
    # Only accept explicitly in-scope events
    in_scope_only = False
    # Only accept the initial target event(s)
    target_only = False
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
        self.__log = None
        self._event_queue = None
        self._batch_idle = 0
        self._futures = set()
        self._future_lock = threading.Lock()

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

    def filter_event(self, event):
        """
        Accept/reject events based on custom criteria

        Override this method if you need more granular control
        over which events your module consumes
        """
        return True

    def handle_batch(self, *events):
        """
        Override this method if batch_size > 1.
        """
        pass

    def finish(self):
        """
        Perform final functions when scan is nearing completion
        Note that this method may be called multiple times
        Optionally override this method.
        """
        return

    def catch(self, callback, *args, **kwargs):
        """
        Wrapper to ensure error messages get surfaced to the user
        """
        try:
            return callback(*args, **kwargs)
        except Exception as e:
            self.error(f"Encountered error in {callback.__name__}(): {e}")
            self.debug(traceback.format_exc())
        except KeyboardInterrupt:
            self.debug(f"Interrupted module {self.name}")
            self.scan.stop()

    def _handle_batch(self, force=False):
        if self.num_queued_events > 0 and (force or self.num_queued_events >= self.batch_size):
            self._batch_idle = 0
            self.debug(
                f'Handling batch of {self.num_queued_events:,} events for module "{self.name}"'
            )
            events = list(self.events_waiting)
            if events:
                self.run_async(self.catch, self.handle_batch, *events)

    def emit_event(self, *args, **kwargs):
        # don't raise an exception if the thread pool has been shutdown
        with suppress(RuntimeError):
            self.helpers.run_async(self._emit_event, *args, **kwargs)

    def _emit_event(self, *args, **kwargs):
        kwargs["module"] = self.name
        event = make_event(*args, **kwargs)

        # special DNS validation
        if event.type == "DNS_NAME":
            resolved = self.helpers.resolve(event.data)
            if not resolved:
                event.tags.add("unresolved")
            if self.helpers.is_wildcard(event.data):
                event.tags.add("wildcard")

        self.debug(f'module "{self.name}" raised {event}')
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
    def num_running_tasks(self):

        running_futures = set()
        with self._future_lock:
            for f in self._futures:
                if not f.done():
                    running_futures.add(f)
            self._futures = running_futures
        return len(running_futures)

    def run_async(self, callback, *args, **kwargs):
        # make sure we don't exceed max threads
        # NOTE: here, we're pulling from the config instead of self.max_threads
        # so the user can change the value if they want
        max_threads = self.config.get("max_threads", None)
        if max_threads is not None:
            while self.num_running_tasks > max_threads:
                sleep(0.1)
        future = self.scan.thread_pool.submit(callback, *args, **kwargs)
        self._futures.add(future)
        return future

    def start(self):
        self.thread = threading.Thread(target=self._worker)
        self.thread.start()

    def _setup(self):

        self.debug(f"Setting up module {self.name}")
        try:
            self.setup()
            self.debug(f"Finished setting up module {self.name}")
        except Exception:
            self.set_error_state()
            self.error(f"Failed to set up module {self.name}")
            self.debug(traceback.format_exc())

    def _worker(self):
        # keep track of how long we've been running
        iterations = 0
        try:
            while not self.scan.stopping:

                iterations += 1
                if self.batch_size > 1:
                    if iterations % 3 == 0:
                        self._batch_idle += 1
                    force = self._batch_idle >= self.batch_wait or self.scan.status == "FINISHING"
                    self._handle_batch(force=force)

                else:
                    try:
                        if self.event_queue:
                            e = self.event_queue.get_nowait()
                        else:
                            self.debug(f'Event queue for module "{self.name}" is in bad state')
                            return
                    except queue.Empty:
                        sleep(0.3333)
                        continue
                    self.debug(f"{self.name}._worker() got {e}")
                    # if we receive the special "FINISHED" event
                    if type(e) == str and e == "FINISHED":
                        self.run_async(self.catch, self.finish)
                    else:
                        self.run_async(self.catch, self.handle_event, e)

        except KeyboardInterrupt:
            self.debug(f"Interrupted module {self.name}")
            self.scan.stop()
        except Exception as e:
            self.error(
                f"Exception ({e.__class__.__name__}) in module {self.name}:\n{traceback.format_exc()}"
            )
            self.set_error_state()

    def _filter_event(self, e):
        if type(e) == str:
            if e == "FINISHED":
                return True
            else:
                return False
        if not any(t in self.watched_events for t in ["*", e.type]):
            return False
        if self.target_only and "target" not in e.tags:
            return False
        if self.in_scope_only and e not in self.scan.target:
            return False
        if not self.filter_event(e):
            return False
        return True

    def queue_event(self, e):
        if self.event_queue is not None and not self.errored:
            if self._filter_event(e):
                self.event_queue.put(e)
        else:
            self.debug(f"Module {self.name} is not in an acceptable state to queue event")

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
        running = (self.num_running_tasks + self.num_queued_events) > 0
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
    def _log(self):
        if self.__log is None:
            self.__log = logging.getLogger(f"bbot.modules.{self.name}")
        return self.__log

    def debug(self, *args, **kwargs):
        self._log.debug(*args, extra={"scan_id": self.scan.id}, **kwargs)

    def verbose(self, *args, **kwargs):
        self._log.verbose(*args, extra={"scan_id": self.scan.id}, **kwargs)

    def info(self, *args, **kwargs):
        self._log.info(*args, extra={"scan_id": self.scan.id}, **kwargs)

    def success(self, *args, **kwargs):
        self._log.success(*args, extra={"scan_id": self.scan.id}, **kwargs)

    def warning(self, *args, **kwargs):
        self._log.warning(*args, extra={"scan_id": self.scan.id}, **kwargs)

    def error(self, *args, **kwargs):
        self._log.error(*args, extra={"scan_id": self.scan.id}, **kwargs)

    def critical(self, *args, **kwargs):
        self._log.critical(*args, extra={"scan_id": self.scan.id}, **kwargs)
