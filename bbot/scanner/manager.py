import queue
import asyncio
import logging
import traceback
from contextlib import suppress

from ..core.helpers.queueing import EventQueue
from ..core.helpers.async_helpers import TaskCounter
from ..core.errors import ScanCancelledError, ValidationError

log = logging.getLogger("bbot.scanner.manager")


class ScanManager:
    """
    Manages modules and events during a scan
    """

    def __init__(self, scan):
        self.scan = scan
        self.incoming_event_queue = EventQueue()

        # tracks duplicate events on a global basis
        self.events_distributed = set()
        # tracks duplicate events on a per-module basis
        self.events_accepted = set()
        self.dns_resolution = self.scan.config.get("dns_resolution", False)
        self._task_counter = TaskCounter()
        self._new_activity = True

    async def init_events(self):
        """
        seed scanner with target events
        """
        with self._task_counter:
            self.distribute_event(self.scan.root_event)
            sorted_events = sorted(self.scan.target.events, key=lambda e: len(e.data))
            for event in sorted_events:
                self.scan.verbose(f"Target: {event}")
                self.queue_event(event)
            # force submit batches
            # for mod in self.scan.modules.values():
            #     mod._handle_batch(force=True)
            self.scan._finished_init = True

    async def emit_event(self, event, *args, **kwargs):
        """
        TODO: Register + kill duplicate events immediately?
        bbot.scanner: scan._event_thread_pool: running for 0 seconds: ScanManager._emit_event(DNS_NAME("sipfed.online.lync.com"))
        bbot.scanner: scan._event_thread_pool: running for 0 seconds: ScanManager._emit_event(DNS_NAME("sipfed.online.lync.com"))
        bbot.scanner: scan._event_thread_pool: running for 0 seconds: ScanManager._emit_event(DNS_NAME("sipfed.online.lync.com"))
        """
        with self._task_counter:
            # skip event if it fails precheck
            if not self._event_precheck(event):
                event._resolved.set()
                return False

            # "quick" queues the event immediately
            quick = kwargs.pop("quick", False)
            if quick:
                log.debug(f'Module "{event.module}" raised {event}')
                event._resolved.set()
                for kwarg in ["abort_if", "on_success_callback", "_block"]:
                    kwargs.pop(kwarg, None)
                try:
                    self.distribute_event(event, *args, **kwargs)
                    return True
                except ScanCancelledError:
                    return False
                except Exception as e:
                    log.error(f"Unexpected error in manager.emit_event(): {e}")
                    log.trace(traceback.format_exc())
            else:
                # don't raise an exception if the thread pool has been shutdown
                error = True
                try:
                    await self.catch(self._emit_event, event, *args, **kwargs)
                    error = False
                    log.debug(f'Module "{event.module}" raised {event}')
                    return True
                except ScanCancelledError:
                    return False
                except Exception as e:
                    log.error(f"Unexpected error in manager.emit_event(): {e}")
                    log.trace(traceback.format_exc())
                finally:
                    if error:
                        event._resolved.set()
            return False

    def _event_precheck(self, event, exclude=("DNS_NAME",)):
        """
        Check an event previous to its DNS resolution etc. to see if we can save on performance by skipping it
        """
        if event._dummy:
            log.warning(f"Cannot emit dummy event: {event}")
            return False
        if event == event.get_source():
            log.debug(f"Skipping event with self as source: {event}")
            return False
        if not event._force_output and self.is_duplicate_event(event):
            log.debug(f"Skipping {event} because it is a duplicate")
            return False
        return True

    async def _emit_event(self, event, *args, **kwargs):
        log.debug(f"Emitting {event}")
        distribute_event = True
        event_distributed = False
        try:
            on_success_callback = kwargs.pop("on_success_callback", None)
            abort_if = kwargs.pop("abort_if", None)

            # skip DNS resolution if it's disabled in the config and the event is a target and we don't have a blacklist
            skip_dns_resolution = (not self.dns_resolution) and "target" in event.tags and not self.scan.blacklist
            if skip_dns_resolution:
                event._resolved.set()
                dns_children = {}
                dns_tags = {"resolved"}
                event_whitelisted_dns = True
                event_blacklisted_dns = False
                resolved_hosts = []
            else:
                # DNS resolution
                (
                    dns_tags,
                    event_whitelisted_dns,
                    event_blacklisted_dns,
                    dns_children,
                ) = await self.scan.helpers.dns.resolve_event(event, minimal=not self.dns_resolution)
                resolved_hosts = set()
                for rdtype, ips in dns_children.items():
                    if rdtype in ("A", "AAAA", "CNAME"):
                        for ip in ips:
                            resolved_hosts.add(ip)

            # kill runaway DNS chains
            dns_resolve_distance = getattr(event, "dns_resolve_distance", 0)
            if dns_resolve_distance >= self.scan.helpers.dns.max_dns_resolve_distance:
                log.debug(
                    f"Skipping DNS children for {event} because their DNS resolve distances would be greater than the configured value for this scan ({self.scan.helpers.dns.max_dns_resolve_distance})"
                )
                dns_children = {}

            # We do this again in case event.data changed during resolve_event()
            if event.type == "DNS_NAME" and not self._event_precheck(event, exclude=()):
                log.debug(f"Omitting due to failed precheck: {event}")
                distribute_event = False

            if event.type in ("DNS_NAME", "IP_ADDRESS"):
                for tag in dns_tags:
                    event.add_tag(tag)

            event._resolved_hosts = resolved_hosts

            event_whitelisted = event_whitelisted_dns | self.scan.whitelisted(event)
            event_blacklisted = event_blacklisted_dns | self.scan.blacklisted(event)
            if event_blacklisted:
                event.add_tag("blacklisted")

            # Blacklist purging
            if "blacklisted" in event.tags:
                reason = "event host"
                if event_blacklisted_dns:
                    reason = "DNS associations"
                log.debug(f"Omitting due to blacklisted {reason}: {event}")
                distribute_event = False

            # DNS_NAME --> DNS_NAME_UNRESOLVED
            if event.type == "DNS_NAME" and "unresolved" in event.tags and not "target" in event.tags:
                event.type = "DNS_NAME_UNRESOLVED"

            # Cloud tagging
            for provider in self.scan.helpers.cloud.providers.values():
                provider.tag_event(event)

            # Scope shepherding
            event_is_duplicate = self.is_duplicate_event(event)
            event_in_report_distance = event.scope_distance <= self.scan.scope_report_distance
            set_scope_distance = event.scope_distance
            if event_whitelisted:
                set_scope_distance = 0
            if event.host:
                if (event_whitelisted or event_in_report_distance) and (event._force_output or not event_is_duplicate):
                    if set_scope_distance == 0:
                        log.debug(f"Making {event} in-scope")
                    source_trail = event.make_in_scope(set_scope_distance)
                    for s in source_trail:
                        self.queue_event(s)
                else:
                    if event.scope_distance > self.scan.scope_report_distance:
                        log.debug(
                            f"Making {event} internal because its scope_distance ({event.scope_distance}) > scope_report_distance ({self.scan.scope_report_distance})"
                        )
                        event.make_internal()

            # check for wildcards
            if event.scope_distance <= self.scan.scope_search_distance:
                if not "unresolved" in event.tags:
                    if not self.scan.helpers.is_ip_type(event.host):
                        await self.scan.helpers.dns.handle_wildcard_event(event, dns_children)

            # now that the event is properly tagged, we can finally make decisions about it
            if callable(abort_if):
                abort_result = abort_if(event)
                msg = f"{event.module}: not raising event {event} due to custom criteria in abort_if()"
                with suppress(ValueError, TypeError):
                    abort_result, reason = abort_result
                    msg += f": {reason}"
                if abort_result:
                    log.debug(msg)
                    return

            if not self.accept_event(event):
                return

            # run success callback before distributing event (so it can add tags, etc.)
            if distribute_event:
                if callable(on_success_callback):
                    self.catch(on_success_callback, event)

            if not event.host or (event.always_emit and not event_is_duplicate):
                log.debug(
                    f"Force-emitting {event} because it does not have identifying scope information or because always_emit was True"
                )
                source_trail = event.unmake_internal(force_output=True)
                for s in source_trail:
                    self.queue_event(s)

            if distribute_event:
                self.distribute_event(event)
                event_distributed = True

            # speculate DNS_NAMES and IP_ADDRESSes from other event types
            source_event = event
            if (
                event.host
                and event.type not in ("DNS_NAME", "DNS_NAME_UNRESOLVED", "IP_ADDRESS", "IP_RANGE")
                and not str(event.module) == "speculate"
            ):
                source_module = self.scan.helpers._make_dummy_module("host", _type="internal")
                source_module._priority = 4
                source_event = self.scan.make_event(event.host, "DNS_NAME", module=source_module, source=event)
                # only emit the event if it's not already in the parent chain
                if source_event is not None and source_event not in source_event.get_sources():
                    source_event.scope_distance = event.scope_distance
                    if "target" in event.tags:
                        source_event.add_tag("target")
                    self.queue_event(source_event)

            ### Emit DNS children ###
            if self.dns_resolution:
                emit_children = -1 < event.scope_distance < self.scan.dns_search_distance
                if emit_children:
                    host_hash = hash(str(event.host))
                    if host_hash in self.events_accepted:
                        emit_children = False
                    self.events_accepted.add(host_hash)

                if emit_children:
                    dns_child_events = []
                    if dns_children:
                        for rdtype, records in dns_children.items():
                            module = self.scan.helpers.dns._get_dummy_module(rdtype)
                            module._priority = 4
                            for record in records:
                                try:
                                    child_event = self.scan.make_event(
                                        record, "DNS_NAME", module=module, source=source_event
                                    )
                                    dns_child_events.append(child_event)
                                except ValidationError as e:
                                    log.warning(
                                        f'Event validation failed for DNS child of {source_event}: "{record}" ({rdtype}): {e}'
                                    )
                    for child_event in dns_child_events:
                        self.queue_event(child_event)

        except KeyboardInterrupt:
            self.scan.stop()

        except ValidationError as e:
            log.warning(f"Event validation failed with args={args}, kwargs={kwargs}: {e}")
            log.trace(traceback.format_exc())

        finally:
            event._resolved.set()
            if event_distributed:
                self.scan.stats.event_distributed(event)
            log.debug(f"{event.module}.emit_event() finished for {event}")

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
        """
        Calculate whether an event is a duplicate on a per-module basis
        """
        event_hash = self.hash_event(event)
        suppress_dupes = getattr(event.module, "suppress_dupes", True)
        duplicate_event = suppress_dupes and event_hash in self.events_accepted
        if add:
            self.events_accepted.add(event_hash)
        return duplicate_event

    def accept_event(self, event):
        is_duplicate = self.is_duplicate_event(event, add=True)
        if is_duplicate and not event._force_output:
            log.debug(f"{event.module}: not raising duplicate event {event}")
            return False
        return True

    async def catch(self, callback, *args, **kwargs):
        """
        Wrapper to ensure error messages get surfaced to the user
        """
        ret = None
        on_finish_callback = kwargs.pop("_on_finish_callback", None)
        force = kwargs.pop("_force", False)
        fn = callback
        for arg in args:
            if callable(arg):
                fn = arg
            else:
                break
        try:
            if not self.scan.stopping or force:
                ret = await self.scan.helpers.execute_sync_or_async(callback, *args, **kwargs)
        except ScanCancelledError as e:
            log.debug(f"ScanCancelledError in {fn.__qualname__}(): {e}")
        except BrokenPipeError as e:
            log.debug(f"BrokenPipeError in {fn.__qualname__}(): {e}")
        except Exception as e:
            log.error(f"Error in {fn.__qualname__}(): {e}")
            log.trace(traceback.format_exc())
        except KeyboardInterrupt:
            log.debug(f"Interrupted")
            self.scan.stop()
        except asyncio.CancelledError as e:
            log.debug(f"{e}")
        if callable(on_finish_callback):
            try:
                await self.scan.helpers.execute_sync_or_async(on_finish_callback)
            except Exception as e:
                log.error(
                    f"Error in on_finish_callback {on_finish_callback.__qualname__}() after {fn.__qualname__}(): {e}"
                )
                log.trace(traceback.format_exc())
        return ret

    async def _register_running(self, callback, *args, **kwargs):
        with self._task_counter:
            return await callback(*args, **kwargs)

    def distribute_event(self, *args, **kwargs):
        """
        Queue event with modules
        """
        event = self.scan.make_event(*args, **kwargs)

        event_hash = hash(event)
        dup = event_hash in self.events_distributed
        if dup:
            self.scan.verbose(f"{event.module}: Duplicate event: {event}")
        else:
            self.events_distributed.add(event_hash)
        # absorb event into the word cloud if it's in scope
        if not dup and -1 < event.scope_distance < 1:
            self.scan.word_cloud.absorb_event(event)
        for mod in self.scan.modules.values():
            if not dup or mod.accept_dupes:
                mod.queue_event(event)

    async def _worker_loop(self):
        try:
            while 1:
                try:
                    event, kwargs = self.incoming_event_queue.get_nowait()
                    acceptable = await self.emit_event(event, **kwargs)
                    if acceptable:
                        self._new_activity = True
                except queue.Empty:
                    await asyncio.sleep(0.1)

        except KeyboardInterrupt:
            self.scan.stop()

        except Exception:
            log.critical(traceback.format_exc())

    def queue_event(self, event, **kwargs):
        if event:
            # nerf event's priority if it's likely not to be in scope
            if event.scope_distance > 0:
                event_in_scope = self.scan.whitelisted(event) and not self.scan.blacklisted(event)
                if not event_in_scope:
                    event.module_priority += event.scope_distance
            # Wait for parent event to resolve (in case its scope distance changes)
            # await resolved = event.source._resolved.wait()
            # update event's scope distance based on its parent
            event.scope_distance = event.source.scope_distance + 1
            self.incoming_event_queue.put_nowait((event, kwargs))

    @property
    def running(self):
        return self._task_counter.value > 0 or self.incoming_event_queue.qsize() > 0

    @property
    def modules_finished(self):
        return all(m.finished for m in self.scan.modules.values())

    @property
    def active(self):
        return self.running or not self.modules_finished

    async def modules_status(self, _log=False):
        finished = True
        status = {"modules": {}}

        for m in self.scan.modules.values():
            mod_status = m.status
            if mod_status["running"]:
                finished = False
            status["modules"][m.name] = mod_status

        for mod in self.scan.modules.values():
            if mod.errored and mod.incoming_event_queue not in [None, False]:
                with suppress(Exception):
                    mod.set_error_state()

        status["finished"] = finished

        modules_errored = [m for m, s in status["modules"].items() if s["errored"]]

        if _log:
            modules_status = []
            for m, s in status["modules"].items():
                running = s["running"]
                incoming = s["events"]["incoming"]
                outgoing = s["events"]["outgoing"]
                tasks = s["tasks"]
                total = sum([incoming, outgoing, tasks])
                if running or total > 0:
                    modules_status.append((m, running, incoming, outgoing, tasks, total))
            modules_status.sort(key=lambda x: x[-1], reverse=True)

            if modules_status:
                modules_status_str = ", ".join([f"{m}({i:,}:{t:,}:{o:,})" for m, r, i, o, t, _ in modules_status])
                running_modules_str = ", ".join([m[0] for m in modules_status if m[1]])
                self.scan.info(f"{self.scan.name}: Modules running: {running_modules_str}")
                self.scan.verbose(
                    f"{self.scan.name}: Modules status (incoming:processing:outgoing) {modules_status_str}"
                )
            event_type_summary = sorted(
                self.scan.stats.events_emitted_by_type.items(), key=lambda x: x[-1], reverse=True
            )
            if event_type_summary:
                self.scan.info(
                    f'{self.scan.name}: Events produced so far: {", ".join([f"{k}: {v}" for k,v in event_type_summary])}'
                )
            else:
                self.scan.info(f"{self.scan.name}: No events produced yet")

            if modules_errored:
                self.scan.verbose(
                    f'{self.scan.name}: Modules errored: {len(modules_errored):,} ({", ".join([m for m in modules_errored])})'
                )

            queued_events_by_type = [(k, v) for k, v in self.incoming_event_queue.event_types.items() if v > 0]
            if queued_events_by_type:
                queued_events_by_type.sort(key=lambda x: x[-1], reverse=True)
                queued_events_by_type_str = ", ".join(f"{m}: {t:,}" for m, t in queued_events_by_type)
                self.scan.info(
                    f"{self.scan.name}: {self.incoming_event_queue.qsize():,} events in queue ({queued_events_by_type_str})"
                )
            else:
                self.scan.info(f"{self.scan.name}: No events in queue")

            # Uncomment these lines to enable debugging of event queues

            # queued_events = self.incoming_event_queue.events
            # if queued_events:
            #     queued_events_str = ", ".join(str(e) for e in queued_events)
            #     self.scan.verbose(f"Queued events: {queued_events_str}")
            #     queued_events_by_module = [(k, v) for k, v in self.incoming_event_queue.modules.items() if v > 0]
            #     queued_events_by_module.sort(key=lambda x: x[-1], reverse=True)
            #     queued_events_by_module_str = ", ".join(f"{m}: {t:,}" for m, t in queued_events_by_module)
            #     self.scan.verbose(f"{self.scan.name}: Queued events by module: {queued_events_by_module_str}")

        status.update({"modules_errored": len(modules_errored)})

        return status
