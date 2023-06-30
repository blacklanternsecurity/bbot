import asyncio
import logging
import traceback
from contextlib import suppress

from ..core.errors import ValidationError
from ..core.helpers.async_helpers import TaskCounter

log = logging.getLogger("bbot.scanner.manager")


class ScanManager:
    """
    Manages modules and events during a scan
    """

    def __init__(self, scan):
        self.scan = scan

        self.incoming_event_queue = asyncio.PriorityQueue()

        # tracks duplicate events on a global basis
        self.events_distributed = set()
        # tracks duplicate events on a per-module basis
        self.events_accepted = set()
        self.dns_resolution = self.scan.config.get("dns_resolution", False)
        self._task_counter = TaskCounter()
        self._new_activity = True
        self._modules_by_priority = None
        self._incoming_queues = None
        self._module_priority_weights = None

    async def init_events(self):
        """
        seed scanner with target events
        """
        async with self.scan.acatch(context=self.init_events):
            with self._task_counter:
                await self.distribute_event(self.scan.root_event)
                sorted_events = sorted(self.scan.target.events, key=lambda e: len(e.data))
                for event in sorted_events:
                    self.scan.verbose(f"Target: {event}")
                    self.queue_event(event)
                await asyncio.sleep(0.1)
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
                return

            log.debug(f'Module "{event.module}" raised {event}')

            # "quick" queues the event immediately
            quick = kwargs.pop("quick", False)
            if quick:
                log.debug(f'Module "{event.module}" raised {event}')
                event._resolved.set()
                for kwarg in ["abort_if", "on_success_callback"]:
                    kwargs.pop(kwarg, None)
                async with self.scan.acatch(context=self.distribute_event):
                    await self.distribute_event(event, *args, **kwargs)
            else:
                async with self.scan.acatch(context=self._emit_event, finally_callback=event._resolved.set):
                    await self._emit_event(event, *args, **kwargs)

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

            event_is_duplicate = self.is_duplicate_event(event)

            # Scope shepherding
            # here, we buff or nerf an event based on its attributes and certain scan settings
            event_is_duplicate = self.is_duplicate_event(event)
            event_in_report_distance = event.scope_distance <= self.scan.scope_report_distance
            set_scope_distance = event.scope_distance
            if event_whitelisted:
                set_scope_distance = 0
            if event.host:
                # here, we evaluate some weird logic
                # the reason this exists is to ensure we don't have orphans in the graph
                # because forcefully internalizing certain events can orphan their children
                event_will_be_output = event_whitelisted or event_in_report_distance
                event_is_duplicate = event_is_duplicate and not event._force_output
                if event_will_be_output and not event_is_duplicate:
                    if set_scope_distance == 0:
                        log.debug(f"Making {event} in-scope")
                    source_trail = event.set_scope_distance(set_scope_distance)
                    # force re-emit internal source events
                    for s in source_trail:
                        await self.emit_event(s, _block=False, _force_submit=True)
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
            abort_result = False
            if callable(abort_if):
                async with self.scan.acatch(context=abort_if):
                    abort_result = await self.scan.helpers.execute_sync_or_async(abort_if, event)
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
                    async with self.scan.acatch(context=on_success_callback):
                        await self.scan.helpers.execute_sync_or_async(on_success_callback, event)

            if not event.host or (event.always_emit and not event_is_duplicate):
                log.debug(
                    f"Force-emitting {event} (host:{event.host}, always_emit={event.always_emit}, is_duplicate={event_is_duplicate})"
                )
                source_trail = event.unmake_internal(force_output=True)
                for s in source_trail:
                    self.queue_event(s)

            if distribute_event:
                await self.distribute_event(event)
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
                    # only emit DNS children once for each unique host
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

    async def _register_running(self, callback, *args, **kwargs):
        with self._task_counter:
            return await callback(*args, **kwargs)

    async def distribute_event(self, *args, **kwargs):
        """
        Queue event with modules
        """
        async with self.scan.acatch(context=self.distribute_event):
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
                    await mod.queue_event(event)

    async def _worker_loop(self):
        try:
            while not self.scan.stopped:
                try:
                    event, kwargs = self.get_event_from_modules()
                except asyncio.queues.QueueEmpty:
                    await asyncio.sleep(0.1)
                    continue
                await self.emit_event(event, **kwargs)

        except Exception:
            log.critical(traceback.format_exc())

    @property
    def modules_by_priority(self):
        if not self._modules_by_priority:
            self._modules_by_priority = sorted(list(self.scan.modules.values()), key=lambda m: m.priority)
        return self._modules_by_priority

    @property
    def incoming_queues(self):
        if not self._incoming_queues:
            queues_by_priority = [m.outgoing_event_queue for m in self.modules_by_priority]
            self._incoming_queues = [self.incoming_event_queue] + queues_by_priority
        return self._incoming_queues

    @property
    def module_priority_weights(self):
        if not self._module_priority_weights:
            # we subtract from six because lower priorities == higher weights
            priorities = [5] + [6 - m.priority for m in self.modules_by_priority]
            self._module_priority_weights = priorities
        return self._module_priority_weights

    def get_event_from_modules(self):
        for q in self.scan.helpers.weighted_shuffle(self.incoming_queues, self.module_priority_weights):
            try:
                return q.get_nowait()
            except (asyncio.queues.QueueEmpty, AttributeError):
                continue
        raise asyncio.queues.QueueEmpty()

    @property
    def queued_event_types(self):
        event_types = {}
        for q in self.incoming_queues:
            for event, _ in q._queue:
                event_type = getattr(event, "type", None)
                if event_type is not None:
                    try:
                        event_types[event_type] += 1
                    except KeyError:
                        event_types[event_type] = 1
        return event_types

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
        active_tasks = self._task_counter.value
        incoming_events = self.incoming_event_queue.qsize()
        return active_tasks > 0 or incoming_events > 0

    @property
    def modules_finished(self):
        finished_modules = [m.finished for m in self.scan.modules.values()]
        return all(finished_modules)

    @property
    def active(self):
        return self.running or not self.modules_finished

    def modules_status(self, _log=False):
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

            queued_events_by_type = [(k, v) for k, v in self.queued_event_types.items() if v > 0]
            if queued_events_by_type:
                queued_events_by_type.sort(key=lambda x: x[-1], reverse=True)
                queued_events_by_type_str = ", ".join(f"{m}: {t:,}" for m, t in queued_events_by_type)
                num_queued_events = sum(v for k, v in queued_events_by_type)
                self.scan.info(
                    f"{self.scan.name}: {num_queued_events:,} events in queue ({queued_events_by_type_str})"
                )
            else:
                self.scan.info(f"{self.scan.name}: No events in queue")

            if self.scan.log_level <= logging.DEBUG:
                # status debugging
                scan_active_status = []
                scan_active_status.append(f"scan._finished_init: {self.scan._finished_init}")
                scan_active_status.append(f"manager.active: {self.active}")
                scan_active_status.append(f"    manager.running: {self.running}")
                scan_active_status.append(f"        manager._task_counter.value: {self._task_counter.value}")
                scan_active_status.append(
                    f"        manager.incoming_event_queue.qsize(): {self.incoming_event_queue.qsize()}"
                )
                scan_active_status.append(f"    manager.modules_finished: {self.modules_finished}")
                for m in self.scan.modules.values():
                    scan_active_status.append(f"        {m}.finished: {m.finished}")
                    scan_active_status.append(f"            running: {m.running}")
                    scan_active_status.append(f"            num_incoming_events: {m.num_incoming_events}")
                    scan_active_status.append(
                        f"            outgoing_event_queue.qsize(): {m.outgoing_event_queue.qsize()}"
                    )
                for line in scan_active_status:
                    self.scan.debug(line)

                # log module memory usage
                module_memory_usage = []
                for module in self.scan.modules.values():
                    memory_usage = module.memory_usage
                    module_memory_usage.append((module.name, memory_usage))
                module_memory_usage.sort(key=lambda x: x[-1], reverse=True)
                self.scan.debug(f"MODULE MEMORY USAGE:")
                for module_name, usage in module_memory_usage:
                    self.scan.debug(f"    - {module_name}: {self.scan.helpers.bytes_to_human(usage)}")

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
