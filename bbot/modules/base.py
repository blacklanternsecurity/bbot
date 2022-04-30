import queue
import logging
import threading
import traceback
from time import sleep
from contextlib import suppress

from ..core.threadpool import ThreadPoolWrapper
from ..core.errors import ScanCancelledError, ValidationError


class BaseModule:

    # Event types to watch
    watched_events = []
    # Event types to produce
    produced_events = []
    # Flags
    flags = []
    # python dependencies (pip install ____)
    deps_python = []
    # other dependences as shell commands
    deps_shell = []
    # Whether to accept duplicate events
    accept_dupes = False
    # Whether to block outgoing duplicate events
    suppress_dupes = True
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
    # Type, for differentiating between normal modules and output modules, etc.
    _type = "base"

    def __init__(self, scan):
        self.scan = scan
        self.errored = False
        self._log = None
        self._event_queue = None
        self._batch_idle = 0
        self.thread_pool = ThreadPoolWrapper(self.scan._thread_pool.executor, max_workers=self.max_threads)
        self._internal_thread_pool = ThreadPoolWrapper(
            self.scan._internal_thread_pool.executor, max_workers=self.config.get("max_threads", 1)
        )
        self._emitted_events = set()
        # additional callbacks to be executed alongside self.cleanup()
        self.cleanup_callbacks = []

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

    def handle_batch(self, *events):
        """
        Override this method if batch_size > 1.
        """
        pass

    def filter_event(self, event):
        """
        Accept/reject events based on custom criteria

        Override this method if you need more granular control
        over which events are distributed to your module
        """
        return True

    def finish(self):
        """
        Perform final functions when scan is nearing completion

        For example,  if your module relies on the word cloud, you may choose to wait until
        the scan is finished (and the word cloud is most complete) before running an operation.

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
        on_finish_callback = kwargs.pop("_on_finish_callback", None)
        lock_brutes = kwargs.pop("_lock_brutes", False) and "brute_force" in self.flags
        lock_acquired = False
        try:
            if lock_brutes:
                lock_acquired = self.scan._brute_lock.acquire()
            if not self.scan.stopping:
                ret = callback(*args, **kwargs)
        except ScanCancelledError as e:
            self.debug(f"Encountered ScanCancelledError in {callback.__name__}(): {e}")
        except BrokenPipeError as e:
            self.debug(f"Encountered BrokenPipeError in {callback.__name__}(): {e}")
        except Exception as e:
            self.error(f"Encountered error in {callback.__name__}(): {e}")
            self.debug(traceback.format_exc())
        except KeyboardInterrupt:
            self.debug(f"Interrupted module {self.name}")
            self.scan.stop()
        finally:
            if lock_brutes and lock_acquired:
                self.scan._brute_lock.release()
        if callable(on_finish_callback):
            on_finish_callback()
        return ret

    def _handle_batch(self, force=False):
        if self.num_queued_events > 0 and (force or self.num_queued_events >= self.batch_size):
            self._batch_idle = 0
            on_finish_callback = None
            events, finish = self.events_waiting
            if finish:
                on_finish_callback = self.finish
            if events:
                self.debug(f"Handling batch of {len(events):,} events")
                self._internal_thread_pool.submit_task(
                    self.catch,
                    self.handle_batch,
                    *events,
                    _on_finish_callback=on_finish_callback,
                    _lock_brutes=True,
                )
                return True
        return False

    def emit_event(self, *args, **kwargs):
        # don't raise an exception if the thread pool has been shutdown
        with suppress(RuntimeError):
            self.scan._event_thread_pool.submit_task(self._emit_event, *args, **kwargs)

    def _emit_event(self, *args, **kwargs):
        try:
            on_success_callback = kwargs.pop("on_success_callback", None)
            kwargs["module"] = self
            abort_if_tagged = kwargs.pop("abort_if_tagged", tuple())
            if type(abort_if_tagged) == str:
                abort_if_tagged = (abort_if_tagged,)
            event = self.scan.make_event(*args, **kwargs)
            if self.suppress_dupes and hash(event) in self._emitted_events:
                self.debug(f"Not raising duplicate event {event}")
                return
            self._emitted_events.add(hash(event))

            # special DNS validation
            if event.type == "DNS_NAME":
                resolved = self.helpers.resolve(event.data)
                if any([self.scan.target.in_scope(i) for i in resolved]):
                    event.tags.add("in_scope")
                if resolved:
                    event.tags.add("resolved")
                else:
                    event.tags.add("unresolved")
                if self.helpers.is_wildcard(event.data):
                    event.tags.add("wildcard")

            for tag in abort_if_tagged:
                if tag in event.tags:
                    self.debug(f'Not raising event due to unwanted tag "{tag}"')
                    return

            self.debug(f'module "{self.name}" raised {event}')
            self.scan.manager.queue_event(event)
            if callable(on_success_callback):
                on_success_callback(event)
        except ValidationError as e:
            self.warning(f"Event validation failed with args={args}, kwargs={kwargs}: {e}")

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
        ret = 0
        if self.event_queue:
            ret = self.event_queue.qsize()
        return ret

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
        batch_modules = [m for m in self.scan.modules.values() if m.batch_size > 1]
        if all([(not m.running) for m in batch_modules]):
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
                            self.debug(f"Event queue is in bad state")
                            return
                    except queue.Empty:
                        sleep(0.3333)
                        continue
                    self.debug(f"Got {e}")
                    # if we receive the special "FINISHED" event
                    if type(e) == str and e == "FINISHED":
                        self._internal_thread_pool.submit_task(self.catch, self.finish)
                    else:
                        if self._type == "output":
                            self.catch(self.handle_event, e)
                        else:
                            self._internal_thread_pool.submit_task(self.catch, self.handle_event, e, _lock_brutes=True)

        except KeyboardInterrupt:
            self.debug(f"Interrupted")
            self.scan.stop()
        except ScanCancelledError as e:
            self.verbose(f"Scan cancelled, {e}")
        except Exception as e:
            self.set_error_state(
                f"Exception ({e.__class__.__name__}) in module {self.name}:\n{traceback.format_exc()}"
            )

    def _filter_event(self, e):
        # special "FINISHED" event
        if type(e) == str:
            if e == "FINISHED":
                return True
            else:
                return False
        # exclude non-watched types
        if not any(t in self.watched_events for t in ["*", e.type]):
            return False
        # optionally exclude non-targets
        if self.target_only and "target" not in e.tags:
            return False
        # optionally exclude out-of-scope targets
        if self.in_scope_only and not self.scan.target.in_scope(e):
            return False
        # special case for IPs that originated from a CIDR
        # if the event is an IP address and came from the enricher module
        module_name = getattr(getattr(e, "module", None), "name", "")
        if e.type == "IP_ADDRESS" and module_name == "enricher":
            # and the current module listens for both ranges and CIDRs
            if all([x in self.watched_events for x in [f"IPV{e.version}_RANGE", f"IPV{e.version}_ADDRESS"]]):
                # then skip the event.
                # this avoids double-portscanning both an individual IP and its parent CIDR.
                return False
        # custom filtering
        if not self.filter_event(e):
            return False
        return True

    def _cleanup(self):
        for callback in [self.cleanup] + self.cleanup_callbacks:
            if callable(callback):
                self._internal_thread_pool.submit_task(self.catch, callback)

    def queue_event(self, e):
        if self.event_queue is not None and not self.errored:
            if self._filter_event(e):
                self.event_queue.put(e)
        else:
            self.debug(f"Not in an acceptable state to queue event")

    def set_error_state(self, message=None):
        if message is not None:
            self.error(str(message))
        if not self.errored:
            self.debug(f"Setting error state for module {self.name}")
            self.errored = True
            # clear incoming queue
            if self.event_queue:
                self.debug(f"Emptying event_queue")
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
    def status(self):
        main_pool = self.thread_pool.num_tasks
        internal_pool = self._internal_thread_pool.num_tasks
        pool_total = main_pool + internal_pool
        status = {
            "events": {"queued": self.event_queue.qsize()},
            "tasks": {"main_pool": main_pool, "internal_pool": internal_pool, "total": pool_total},
            "errored": self.errored,
        }
        status["running"] = self._is_running(status)
        return status

    @staticmethod
    def _is_running(module_status):
        for status, count in module_status["events"].items():
            if count > 0:
                return True
        for pool, count in module_status["tasks"].items():
            if count > 0:
                return True
        return False

    @property
    def running(self):
        """
        Indicates whether the module is currently processing data.
        """
        return self._is_running(self.status)

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
    def log(self):
        if self._log is None:
            self._log = logging.getLogger(f"bbot.modules.{self.name}")
        return self._log

    def __str__(self):
        return self.name

    def stdout(self, *args, **kwargs):
        self.log.stdout(*args, extra={"scan_id": self.scan.id}, **kwargs)

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
