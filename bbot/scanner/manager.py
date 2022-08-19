import queue
import logging
import threading
from time import sleep
from contextlib import suppress
from datetime import datetime, timedelta

from ..core.errors import ScanCancelledError, ValidationError

log = logging.getLogger("bbot.scanner.manager")


class ScanManager:
    """
    Manages modules and events during a scan
    """

    def __init__(self, scan):
        self.scan = scan
        self.event_queue = queue.PriorityQueue()
        self.events_distributed = set()
        self.events_distributed_lock = threading.Lock()
        self.events_accepted = set()
        self.events_accepted_lock = threading.Lock()
        self.events_resolved = dict()
        self.events_resolved_lock = threading.Lock()
        self.dns_resolution = self.scan.config.get("dns_resolution", False)

    def init_events(self):
        """
        seed scanner with target events
        """
        self.queue_event(self.scan.root_event)
        for event in self.scan.target.events:
            self.scan.verbose(f"Target: {event}")
            self.emit_event(event)
        # force submit batches
        for mod in self.scan.modules.values():
            mod._handle_batch(force=True)

    def emit_event(self, event, *args, **kwargs):
        quick = kwargs.pop("quick", False)
        release = kwargs.get("release", True)
        if quick:
            try:
                kwargs.pop("abort_if")
                kwargs.pop("on_success_callback")
                self.queue_event(event, *args, **kwargs)
            finally:
                if release:
                    with suppress(Exception):
                        event.module._event_semaphore.release()
        else:
            # don't raise an exception if the thread pool has been shutdown
            with suppress(RuntimeError):
                self.scan._event_thread_pool.submit_task(self.catch, self._emit_event, event, *args, **kwargs)

    def _emit_event(self, event, *args, **kwargs):
        release = kwargs.pop("release", True)
        emit_event = True
        try:
            on_success_callback = kwargs.pop("on_success_callback", None)
            abort_if = kwargs.pop("abort_if", None)
            log.debug(f'module "{event.module}" raised {event}')

            if event._dummy:
                log.warning(f"Cannot emit dummy event: {event}")
                return

            if event == event.get_source():
                log.debug(f"Omitting event with self as source: {event}")
                return

            # DNS resolution
            dns_children, dns_tags, event_whitelisted_dns, event_blacklisted_dns = self.scan.helpers.dns.resolve_event(
                event
            )
            event_whitelisted = event_whitelisted_dns | self.scan.whitelisted(event)
            event_blacklisted = event_blacklisted_dns | self.scan.blacklisted(event)
            if event.type in ("DNS_NAME", "IP_ADDRESS"):
                event.tags.update(dns_tags)
            if event_blacklisted:
                event.tags.add("blacklisted")

            # Blacklist purging
            if "blacklisted" in event.tags:
                reason = "event host"
                if event_blacklisted_dns:
                    reason = "DNS associations"
                log.debug(f"Omitting due to blacklisted {reason}: {event}")
                emit_event = False

            # Wait for parent event to resolve (in case its scope distance changes)
            while 1:
                if self.scan.stopping:
                    raise ScanCancelledError()
                resolved = event._resolved.wait(timeout=0.1)
                if resolved:
                    # update event's scope distance based on its parent
                    event.scope_distance = event.source.scope_distance + 1
                    break

            # Scope shepherding
            event_is_duplicate = self.is_duplicate_event(event)
            event_in_report_distance = event.scope_distance <= self.scan.scope_report_distance
            set_scope_distance = event.scope_distance
            if event_whitelisted:
                set_scope_distance = 0
            if event.host:
                if (event_whitelisted or event_in_report_distance) and not event_is_duplicate:
                    if set_scope_distance == 0:
                        log.debug(f"Making {event} in-scope")
                    event.make_in_scope(set_scope_distance)
                else:
                    if event.scope_distance > self.scan.scope_report_distance:
                        log.debug(
                            f"Making {event} internal because its scope_distance ({event.scope_distance}) > scope_report_distance ({self.scan.scope_report_distance})"
                        )
                        event.make_internal()
            else:
                log.debug(f"Making {event} in-scope because it does not have identifying scope information")
                event.make_in_scope(0)

            # now that the event is properly tagged, we can finally make decisions about it
            if callable(abort_if) and abort_if(event):
                log.debug(f"{event.module}: not raising event {event} due to custom criteria in abort_if()")
                return

            if not self.accept_event(event):
                return

            # queue the event before emitting its DNS children
            if emit_event:
                self.queue_event(event)

            if callable(on_success_callback):
                self.catch(on_success_callback, event)

            ### Emit DNS children ###
            emit_children = -1 < event.scope_distance < self.scan.dns_search_distance
            # speculate DNS_NAMES and IP_ADDRESSes from other event types
            source_event = event
            if event.host and event.type not in ("DNS_NAME", "IP_ADDRESS", "IP_RANGE"):
                source_module = self.scan.helpers._make_dummy_module("host", _type="internal")
                source_event = self.scan.make_event(event.host, "DNS_NAME", module=source_module, source=event)
                source_event.scope_distance = event.scope_distance
                if "target" in event.tags:
                    source_event.tags.add("target")
                if not str(event.module) == "speculate":
                    self.emit_event(source_event)
            if self.dns_resolution and emit_children:
                dns_child_events = []
                if dns_children:
                    for record, rdtype in dns_children:
                        module = self.scan.helpers.dns._get_dummy_module(rdtype)
                        try:
                            child_event = self.scan.make_event(record, "DNS_NAME", module=module, source=source_event)
                            dns_child_events.append(child_event)
                        except ValidationError as e:
                            log.warning(
                                f'Event validation failed for DNS child of {source_event}: "{record}" ({rdtype}): {e}'
                            )
                for child_event in dns_child_events:
                    self.emit_event(child_event)

        except ValidationError as e:
            log.warning(f"Event validation failed with args={args}, kwargs={kwargs}: {e}")
            import traceback

            log.debug(traceback.format_exc())

        finally:
            if release:
                with suppress(Exception):
                    event.module._event_semaphore.release()
                if emit_event:
                    self.scan.stats.event_emitted(event)

    def hash_event(self, event):
        """
        Hash an event for duplicate detection

        This is necessary because duplicate events from certain sources (e.g. DNS)
            need to be allowed in order to preserve their relationship trail
        """
        module_type = getattr(event.module, "_type", "")
        if module_type == "DNS":
            # allow duplicate events from dns resolution as long as their source event is unique
            return hash((event, str(event.module), event.source_id))
        else:
            return hash((event, str(event.module)))

    def is_duplicate_event(self, event, add=False):
        event_hash = self.hash_event(event)
        suppress_dupes = getattr(event.module, "suppress_dupes", True)
        with self.events_accepted_lock:
            duplicate_event = suppress_dupes and event_hash in self.events_accepted
            if add:
                self.events_accepted.add(event_hash)
        return duplicate_event and not event._force_output

    def accept_event(self, event):
        if self.is_duplicate_event(event, add=True):
            log.debug(f"{event.module}: not raising duplicate event {event}")
            return False
        return True

    def catch(self, callback, *args, **kwargs):
        """
        Wrapper to ensure error messages get surfaced to the user
        """
        ret = None
        on_finish_callback = kwargs.pop("_on_finish_callback", None)
        force = kwargs.pop("_force", False)
        try:
            if not self.scan.stopping or force:
                ret = callback(*args, **kwargs)
        except ScanCancelledError as e:
            log.debug(f"ScanCancelledError in {callback.__qualname__}(): {e}")
        except BrokenPipeError as e:
            log.debug(f"BrokenPipeError in {callback.__qualname__}(): {e}")
        except Exception as e:
            import traceback

            log.error(f"Error in {callback.__qualname__}(): {e}")
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
                    f"Error in on_finish_callback {on_finish_callback.__qualname__}() after {callback.__qualname__}(): {e}"
                )
                log.debug(traceback.format_exc())
        return ret

    def queue_event(self, *args, **kwargs):
        """
        Queue event with manager
        """
        event = self.scan.make_event(*args, **kwargs)
        self.event_queue.put(event)

    def distribute_event(self, event):
        """
        Queue event with modules
        """
        # TODO: save memory by removing reference to source object (this causes bugs)
        # if not event._internal:
        #    event._source = None

        dup = False
        event_hash = hash(event)
        # with self.events_distributed_lock:
        if event_hash in self.events_distributed:
            self.scan.verbose(f"{event.module}: Duplicate event: {event}")
            dup = True
        else:
            self.events_distributed.add(event_hash)
        # absorb event into the word cloud if it's in scope
        if not dup and -1 < event.scope_distance < 1:
            self.scan.word_cloud.absorb_event(event)
        stats_recorded = False
        for mod in self.scan.modules.values():
            if not dup or mod.accept_dupes:
                event_within_scope_distance = -1 < event.scope_distance <= self.scan.scope_search_distance
                event_within_report_distance = -1 < event.scope_distance <= self.scan.scope_report_distance
                if mod._type == "output":
                    if event_within_report_distance or (event._force_output and mod.emit_graph_trail):
                        mod.queue_event(event)
                        if not stats_recorded:
                            stats_recorded = True
                            self.scan.stats.event_produced(event)
                else:
                    if event_within_scope_distance:
                        mod.queue_event(event)

    def loop_until_finished(self):

        counter = 0
        event_counter = 0
        timedelta_2secs = timedelta(seconds=2)
        last_log_time = datetime.now()

        reported = False
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

                # print status every 2 seconds
                now = datetime.now()
                time_since_last_log = now - last_log_time
                if time_since_last_log > timedelta_2secs:
                    self.modules_status(_log=True, passes=1)
                    last_log_time = now

                try:
                    event = self.event_queue.get_nowait()
                    event_counter += 1
                except queue.Empty:
                    finished = self.modules_status().get("finished", False)
                    if finished and reported:
                        break
                    # If the scan finished
                    if finished:
                        # If new events were generated in the last iteration
                        if event_counter > 0:
                            self.scan.status = "FINISHING"
                            # Trigger .finished() on every module and start over
                            for mod in self.scan.modules.values():
                                mod.queue_event("FINISHED")
                            event_counter = 0
                        elif not reported:
                            # Run .report() on every module and start over
                            for mod in self.scan.modules.values():
                                self.catch(mod.report)
                            reported = True
                        else:
                            # Otherwise stop the scan if no new events were generated in this iteration
                            break
                    else:
                        # save on CPU
                        sleep(0.01)
                    counter += 1
                    continue

                # distribute event to modules
                self.distribute_event(event)

        except KeyboardInterrupt:
            self.scan.stop()

        except Exception:
            import traceback

            log.critical(traceback.format_exc())

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

            for num_events in status["scan"]["queued_events"].values():
                if num_events > 0:
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

            passes -= 1
            if finished and passes > 0:
                sleep(0.1)
            else:
                break

        status["finished"] = finished

        modules_running = [m for m, s in status["modules"].items() if s["running"]]
        modules_errored = [m for m, s in status["modules"].items() if s["errored"]]

        if _log:
            events_queued = [
                (m, (s["events"]["incoming"], s["events"]["outgoing"])) for m, s in status["modules"].items()
            ]
            events_queued.sort(key=lambda x: sum(x[-1]), reverse=True)
            events_queued = [(m, q) for m, q in events_queued if sum(q) > 0][:5]
            events_queued_str = ""
            if events_queued:
                events_queued_str = " (" + ", ".join([f"{m}: I:{i:,} O:{o:,}" for m, (i, o) in events_queued]) + ")"
            tasks_queued = [(m, s["tasks"]["total"]) for m, s in status["modules"].items()]
            tasks_queued.sort(key=lambda x: x[-1], reverse=True)
            tasks_queued = [(m, q) for m, q in tasks_queued if q > 0][:5]
            tasks_queued_str = ""
            if tasks_queued:
                tasks_queued_str = " (" + ", ".join([f"{m}: {q:,}" for m, q in tasks_queued]) + ")"

            num_events_queued = sum([sum(m[-1]) for m in events_queued])
            self.scan.hugeverbose(f"Events queued: {num_events_queued:,}{events_queued_str}")

            num_tasks_queued = sum([m[-1] for m in tasks_queued])
            self.scan.hugeverbose(f"Module tasks queued: {num_tasks_queued:,}{tasks_queued_str}")

            num_scan_tasks = status["scan"]["queued_tasks"]["total"]
            dns_tasks = status["scan"]["queued_tasks"]["dns"]
            event_tasks = status["scan"]["queued_tasks"]["event"]
            main_tasks = status["scan"]["queued_tasks"]["main"]
            internal_tasks = status["scan"]["queued_tasks"]["internal"]
            manager_events_queued = status["scan"]["queued_events"]["manager"]
            self.scan.hugeverbose(
                f"Scan tasks queued: {num_scan_tasks:,} (Main: {main_tasks:,}, Events: {event_tasks:,} waiting, {manager_events_queued:,} in queue, DNS: {dns_tasks:,}, Internal: {internal_tasks:,})"
            )

            if modules_running:
                self.scan.hugeverbose(
                    f'Modules running: {len(modules_running):,} ({", ".join([m for m in modules_running])})'
                )
            if modules_errored:
                self.scan.hugeverbose(
                    f'Modules errored: {len(modules_errored):,} ({", ".join([m for m in modules_errored])})'
                )

        status.update({"modules_running": len(modules_running), "modules_errored": len(modules_errored)})

        return status
