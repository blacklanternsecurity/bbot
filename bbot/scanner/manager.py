import queue
import logging
import threading
from time import sleep
from contextlib import suppress

from ..core.errors import ScanCancelledError, ValidationError

log = logging.getLogger("bbot.scanner.manager")


class ScanManager:
    """
    Manages modules and events during a scan
    """

    def __init__(self, scan):
        self.scan = scan
        self.event_queue = queue.SimpleQueue()
        self.events_distributed = set()
        self.events_distributed_lock = threading.Lock()
        self.events_accepted = set()
        self.events_accepted_lock = threading.Lock()
        self.events_resolved = set()
        self.events_resolved_lock = threading.Lock()

    def init_events(self):
        """
        seed scanner with target events
        """
        self.queue_event(self.scan.root_event)
        for event in self.scan.target.events:
            self.scan.info(f"Target: {event}")
            self.emit_event(event)
        # force submit batches
        for mod in self.scan.modules.values():
            mod._handle_batch(force=True)

    def emit_event(self, *args, **kwargs):
        # don't raise an exception if the thread pool has been shutdown
        with suppress(RuntimeError):
            self.scan._event_thread_pool.submit_task(self.catch, self._emit_event, *args, **kwargs)

    def _emit_event(self, *args, **kwargs):
        try:
            on_success_callback = kwargs.pop("on_success_callback", None)
            abort_if = kwargs.pop("abort_if", lambda e: False)
            event = self.scan.make_event(*args, **kwargs)
            log.debug(f"Emitting event: {event}")

            target = getattr(self.scan, "target", None)
            if target and not event._dummy:
                if target.in_scope(event):
                    source_trail = event.make_in_scope()
                    for s in source_trail:
                        self.emit_event(s)

            # accept the event right away if there's no abort condition
            # if there's an abort condition, we want to wait until DNS
            # it's been properly tagged and the abort_if callback has run
            if abort_if is None:
                if not self.accept_event(event):
                    return

            # DNS resolution
            child_events = []
            dns_event_hash = hash(event)
            resolve_event = True
            # skip DNS resolution if we've already resolved this event
            with self.events_resolved_lock:
                if dns_event_hash in self.events_resolved:
                    resolve_event = False
            if resolve_event and event.type in ("DNS_NAME", "IP_ADDRESS"):
                child_events, source_trail = self.scan.helpers.dns.resolve_event(event)
                # reveal the trail of source events if we found an in-scope host that was previously internal
                for s in source_trail:
                    self.emit_event(s)

            if abort_if(event):
                log.debug(f"{event.module}: not raising event {event} due to custom criteria in abort_if()")
                return

            # now that the event is tagged, accept it if we didn't already
            if abort_if is not None:
                if not self.accept_event(event):
                    return

            log.debug(f'module "{event.module}" raised {event}')
            self.queue_event(event)

            if callable(on_success_callback):
                self.catch(on_success_callback, event)

            emit_children = self.scan.config.get("dns_resolution", False)
            with self.events_resolved_lock:
                # don't emit duplicates
                if emit_children and child_events and dns_event_hash not in self.events_resolved:
                    self.events_resolved.add(dns_event_hash)
                    emit_children &= True
                else:
                    emit_children &= False
            if child_events:
                any_in_scope = any([self.scan.target.in_scope(e) for e in child_events])
                # only emit children if the source event is less than three hops from the main scope
                # this helps prevent runaway dns resolutions that result in junk data
                emit_children &= -1 < event.scope_distance < 3 or any_in_scope
            for child_event in child_events:
                if emit_children:
                    # make child events internal if the source event is not in scope
                    internal_event = event.scope_distance < 0 or event.scope_distance > 0
                    self.emit_event(child_event, internal=internal_event)

        except ValidationError as e:
            log.warning(f"Event validation failed with args={args}, kwargs={kwargs}: {e}")

    def accept_event(self, event):
        if event.module._type == "DNS":
            # allow duplicate events from dns resolution as long as their source event is unique
            event_hash = hash((event, str(event.module), event.source))
        else:
            event_hash = hash((event, str(event.module)))

        with self.events_accepted_lock:
            if event.module.suppress_dupes and event_hash in self.events_accepted:
                log.debug(f"{event.module}: not raising duplicate event {event}")
                return False
            self.events_accepted.add(event_hash)
        return True

    def catch(self, callback, *args, **kwargs):
        """
        Wrapper to ensure error messages get surfaced to the user
        """
        ret = None
        on_finish_callback = kwargs.pop("_on_finish_callback", None)
        try:
            if not self.scan.stopping:
                ret = callback(*args, **kwargs)
        except ScanCancelledError as e:
            log.debug(f"ScanCancelledError in {callback.__name__}(): {e}")
        except BrokenPipeError as e:
            log.debug(f"BrokenPipeError in {callback.__name__}(): {e}")
        except Exception as e:
            import traceback

            log.error(f"Error in {callback.__name__}(): {e}")
            log.debug(traceback.format_exc())
        except KeyboardInterrupt:
            log.debug(f"Interrupted")
            self.scan.stop()
        if callable(on_finish_callback):
            try:
                on_finish_callback()
            except Exception as e:
                import traceback

                log.error(
                    f"Error in on_finish_callback {on_finish_callback.__name__}() after {callback.__name__}(): {e}"
                )
                log.debug(traceback.format_exc())
        return ret

    def queue_event(self, event):
        """
        Queue event with manager
        """
        # remove reference to source object
        if not event._internal:
            event.source_obj = None
        self.event_queue.put(event)

    def distribute_event(self, event):
        """
        Queue event with modules
        """
        dup = False
        event_hash = hash(event)
        with self.events_distributed_lock:
            if event_hash in self.events_distributed:
                self.scan.verbose(f"{event.module}: Duplicate event: {event}")
                dup = True
            else:
                self.events_distributed.add(event_hash)
        if not dup:
            self.scan.word_cloud.absorb_event(event)
        for mod in self.scan.modules.values():
            if not dup or mod.accept_dupes:
                mod.queue_event(event)

    def loop_until_finished(self):

        counter = 0
        event_counter = 0

        try:
            self.scan.dispatcher.on_start(self.scan)

            # watch for newly-generated events
            while 1:

                if self.scan.status == "ABORTING":
                    while 1:
                        try:
                            # Empty event queue
                            self.event_queue.get_nowait()
                        except queue.Empty:
                            break
                    break

                event = False
                # print status every 2 seconds
                log_status = counter % 20 == 0

                try:
                    event = self.event_queue.get_nowait()
                    event_counter += 1
                except queue.Empty:
                    finished = self.modules_status(_log=log_status).get("finished", False)
                    # If the scan finished
                    if finished:
                        # If new events were generated in the last iteration
                        if event_counter > 0:
                            self.scan.status = "FINISHING"
                            # Trigger .finished() on every module and start over
                            for mod in self.scan.modules.values():
                                mod.queue_event("FINISHED")
                            event_counter = 0
                            sleep(1)
                        else:
                            # Otherwise stop the scan if no new events were generated in this iteration
                            break
                    else:
                        # save on CPU
                        sleep(0.1)
                    counter += 1
                    continue

                # distribute event to modules
                self.distribute_event(event)

        except KeyboardInterrupt:
            self.scan.stop()

        finally:
            # clean up modules
            self.scan.status = "CLEANING_UP"
            for mod in self.scan.modules.values():
                mod._cleanup()
            finished = False
            while 1:
                finished = self.modules_status().get("finished", False)
                if finished:
                    break
                else:
                    sleep(0.1)

    def modules_status(self, _log=False, passes=None):

        # If scan looks to be finished, check an additional five times to ensure that it really is
        # There is a tiny chance of a race condition, which this helps to avoid
        if passes is None:
            passes = 5
        else:
            passes = max(1, int(passes))

        finished = True
        while passes > 0:

            status = {"modules": {}, "scan": self.scan.status_detailed}

            if self.event_queue.qsize() > 0:
                finished = False

            for num_tasks in status["scan"]["queued_tasks"].values():
                if num_tasks > 0:
                    finished = False

            for m in self.scan.modules.values():
                mod_status = m.status
                if mod_status["running"]:
                    finished = False
                status["modules"][m.name] = mod_status

            for mod in self.scan.modules.values():
                if mod.errored and mod.event_queue not in [None, False]:
                    with suppress(Exception):
                        mod.set_error_state()

            if finished:
                sleep(0.1)
            else:
                break
            passes -= 1

        status["finished"] = finished

        modules_running = [m for m, s in status["modules"].items() if s["running"]]
        modules_errored = [m for m, s in status["modules"].items() if s["errored"]]

        if _log:
            events_queued = [(m, s["events"]["queued"]) for m, s in status["modules"].items()]
            events_queued.sort(key=lambda x: x[-1], reverse=True)
            events_queued = [(m, q) for m, q in events_queued if q > 0][:5]
            events_queued_str = ""
            if events_queued:
                events_queued_str = " (" + ", ".join([f"{m}: {q:,}" for m, q in events_queued]) + ")"
            tasks_queued = [(m, s["tasks"]["total"]) for m, s in status["modules"].items()]
            tasks_queued.sort(key=lambda x: x[-1], reverse=True)
            tasks_queued = [(m, q) for m, q in tasks_queued if q > 0][:5]
            tasks_queued_str = ""
            if tasks_queued:
                tasks_queued_str = " (" + ", ".join([f"{m}: {q:,}" for m, q in tasks_queued]) + ")"

            num_events_queued = sum([m[-1] for m in events_queued])
            self.scan.verbose(f"Events queued: {num_events_queued:,}{events_queued_str}")

            num_tasks_queued = sum([m[-1] for m in tasks_queued])
            self.scan.verbose(f"Module tasks queued: {num_tasks_queued:,}{tasks_queued_str}")

            num_scan_tasks = status["scan"]["queued_tasks"]["total"]
            dns_tasks = status["scan"]["queued_tasks"]["dns"]
            event_tasks = status["scan"]["queued_tasks"]["event"]
            main_tasks = status["scan"]["queued_tasks"]["main"]
            internal_tasks = status["scan"]["queued_tasks"]["internal"]
            self.scan.verbose(
                f"Scan tasks queued: {num_scan_tasks:,} (Main: {main_tasks:,}, Event: {event_tasks:,}, DNS: {dns_tasks:,}, Internal: {internal_tasks:,})"
            )

            if modules_running:
                self.scan.verbose(
                    f'Modules running: {len(modules_running):,} ({", ".join([m for m in modules_running])})'
                )
            if modules_errored:
                self.scan.verbose(
                    f'Modules errored: {len(modules_errored):,} ({", ".join([m for m in modules_errored])})'
                )

        status.update({"modules_running": len(modules_running), "modules_errored": len(modules_errored)})

        return status
