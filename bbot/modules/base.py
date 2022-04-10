import queue
import logging
import threading
import traceback
from time import sleep
from contextlib import suppress

from ..core.errors import ScanCancelledError


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
    # Maximum concurrent instances of handle_event() or handle_batch()
    max_event_handlers = 1
    # Max number of concurrent calls to submit_task()
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
        self._submit_task_lock = threading.Lock()

    def setup(self):
        """
        Perform setup functions at the beginning of the scan.
        Optionally override this method.

        Must return True or False based on whether the setup was successful
        """
        return True

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
        Note that this method may be called multiple times, because it may raise events.
        Optionally override this method.
        """
        return

    def cleanup(self):
        """
        Perform final cleanup after the scan has finished
        This method is called only once, and may not raise events.
        Optionally override this method.
        """
        return

    def catch(self, callback, *args, **kwargs):
        """
        Wrapper to ensure error messages get surfaced to the user
        """
        ret = None
        on_finish_callback = kwargs.pop("on_finish_callback", None)
        try:
            ret = callback(*args, **kwargs)
        except Exception as e:
            self.error(f"Encountered error in {callback.__name__}(): {e}")
            self.debug(traceback.format_exc())
        except KeyboardInterrupt:
            self.debug(f"Interrupted module {self.name}")
            self.scan.stop()
        if callable(on_finish_callback):
            on_finish_callback()
        return ret

    def _handle_batch(self, force=False):
        if self.num_queued_events > 0 and (force or self.num_queued_events >= self.batch_size):
            self._batch_idle = 0
            self.debug(
                f'Handling batch of {self.num_queued_events:,} events for module "{self.name}"'
            )
            on_finish_callback = None
            events, finish = self.events_waiting
            if finish:
                on_finish_callback = self.finish
            if events:
                self.submit_task(
                    self.catch, self.handle_batch, *events, on_finish_callback=on_finish_callback
                )
                return True
        return False

    def emit_event(self, *args, **kwargs):
        # don't raise an exception if the thread pool has been shutdown
        with suppress(RuntimeError):
            self.helpers.submit_task(self._emit_event, *args, **kwargs)

    def _emit_event(self, *args, **kwargs):
        kwargs["module"] = self
        event = self.scan.make_event(*args, **kwargs)

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
        events = []
        finish = False
        left = int(self.batch_size)
        while left > 0:
            try:
                event = self.event_queue.get_nowait()
                if type(event) == str and event == "FINISHED":
                    finish = True
                else:
                    left -= 1
                    events.append(event)
            except queue.Empty:
                break
        return events, finish

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

    def submit_task(self, callback, *args, **kwargs):
        # make sure we don't exceed max threads for module
        # NOTE: here, we're pulling from the config instead of self.max_threads
        # so the user can change the value if they want
        with self._submit_task_lock:
            while self.num_running_tasks > self.max_threads:
                sleep(0.1)
            try:
                future = self.scan._thread_pool.submit(callback, *args, **kwargs)
            except RuntimeError as e:
                raise ScanCancelledError(e)
            self._futures.add(future)
        return future

    def start(self):
        self.thread = threading.Thread(target=self._worker)
        self.thread.start()

    def _setup(self):

        ret = False
        self.debug(f"Setting up module {self.name}")
        try:
            ret = self.setup()
            self.debug(f"Finished setting up module {self.name}")
        except Exception:
            self.set_error_state(f"Failed to set up module {self.name}")
            self.debug(traceback.format_exc())
        return ret

    @property
    def _force_batch(self):
        """
        Determine whether a batch should be forcefully submitted
        """
        # if we've been idle long enough
        if self._batch_idle >= self.batch_wait:
            return True
        # if scan is finishing
        if self.scan.status == "FINISHING":
            return True
        # if there's a batch stalemate
        modules_status = self.scan.manager.modules_status(passes=1)
        modules_running = modules_status.get("modules_running", [])
        if all([(not m.running) and (m.batch_size > 1) for m in modules_running]):
            return True
        return False

    def _worker(self):
        # keep track of how long we've been running
        iterations = 0
        try:
            while not self.scan.stopping:
                iterations += 1
                if self.batch_size > 1:
                    if iterations % 3 == 0:
                        self._batch_idle += 1
                    force = self._force_batch
                    if force:
                        self._batch_idle = 0
                    submitted = self._handle_batch(force=force)
                    if not submitted:
                        sleep(0.3333)

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
                        self.submit_task(self.catch, self.finish)
                    else:
                        self.submit_task(self.catch, self.handle_event, e)

        except KeyboardInterrupt:
            self.debug(f"Interrupted module {self.name}")
            self.scan.stop()
        except ScanCancelledError as e:
            self.verbose(f"Scan cancelled, {e}")
        except Exception as e:
            self.set_error_state(
                f"Exception ({e.__class__.__name__}) in module {self.name}:\n{traceback.format_exc()}"
            )

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

    def _cleanup(self):
        self.submit_task(self.catch, self.cleanup)

    def queue_event(self, e):
        if self.event_queue is not None and not self.errored:
            if self._filter_event(e):
                self.event_queue.put(e)
        else:
            self.debug(f"Module {self.name} is not in an acceptable state to queue event")

    def set_error_state(self, message=None):
        if message is not None:
            self.error(str(message))
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
        config = self.scan.config.get("modules", {}).get(self.name, {})
        if config is None:
            config = {}
        return config

    @property
    def event_queue(self):
        if self._event_queue is None:
            self._event_queue = queue.SimpleQueue()
        return self._event_queue

    @property
    def _log(self):
        if self.__log is None:
            self.__log = logging.getLogger(f"bbot.modules.{self.name}")
        return self.__log

    def __str__(self):
        return self.name

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
