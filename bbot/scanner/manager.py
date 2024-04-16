import asyncio
import logging
from contextlib import suppress

from bbot.modules.base import InterceptModule

log = logging.getLogger("bbot.scanner.manager")


class ScanIngress(InterceptModule):
    """
    This is always the first intercept module in the chain, responsible for basic scope checks

    It has its own incoming queue, but will also pull events from modules' outgoing queues
    """

    watched_events = ["*"]
    # accept all events regardless of scope distance
    scope_distance_modifier = None
    _name = "_scan_ingress"

    @property
    def priority(self):
        # we are the highest priority
        return -99

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._module_priority_weights = None
        self._non_hook_modules = None
        # track incoming duplicates module-by-module (for `suppress_dupes` attribute of modules)
        self.incoming_dup_tracker = set()

    async def init_events(self, events):
        """
        Initializes events by seeding the scanner with target events and distributing them for further processing.

        Notes:
            - This method populates the event queue with initial target events.
            - It also marks the Scan object as finished with initialization by setting `_finished_init` to True.
        """
        async with self.scan._acatch(self.init_events), self._task_counter.count(self.init_events):
            sorted_events = sorted(events, key=lambda e: len(e.data))
            for event in [self.scan.root_event] + sorted_events:
                event._dummy = False
                event.scope_distance = 0
                event.web_spider_distance = 0
                event.scan = self.scan
                if event.source is None:
                    event.source = self.scan.root_event
                if event.module is None:
                    event.module = self.scan._make_dummy_module(name="TARGET", _type="TARGET")
                self.verbose(f"Target: {event}")
                await self.queue_event(event, {})
            await asyncio.sleep(0.1)
            self.scan._finished_init = True

    async def handle_event(self, event, kwargs):
        # don't accept dummy events
        if event._dummy:
            return False, "cannot emit dummy event"

        # don't accept events with self as source
        if (not event.type == "SCAN") and (event == event.get_source()):
            return False, "event's source is itself"

        # don't accept duplicates
        if (not event._graph_important) and self.is_incoming_duplicate(event, add=True):
            return False, "event was already emitted by its module"

        # update event's scope distance based on its parent
        event.scope_distance = event.source.scope_distance + 1

        # blacklist rejections
        event_blacklisted = self.scan.blacklisted(event)
        if event_blacklisted or "blacklisted" in event.tags:
            return False, f"Omitting blacklisted event: {event}"

        # Scope shepherding
        # here is where we make sure in-scope events are set to their proper scope distance
        event_whitelisted = self.scan.whitelisted(event)
        if event.host and event_whitelisted:
            log.debug(f"Making {event} in-scope because it matches the scan target")
            event.scope_distance = 0

        # nerf event's priority if it's not in scope
        event.module_priority += event.scope_distance

    async def forward_event(self, event, kwargs):
        # if a module qualifies for "quick-emit", we skip all the intermediate modules like dns and cloud
        # and forward it straight to the egress module
        if event.quick_emit:
            await self.scan.egress_module.queue_event(event, kwargs)
        else:
            await super().forward_event(event, kwargs)

    @property
    def non_hook_modules(self):
        if self._non_hook_modules is None:
            self._non_hook_modules = [m for m in self.scan.modules.values() if not m._hook]
        return self._non_hook_modules

    @property
    def incoming_queues(self):
        return [self.incoming_event_queue] + [m.outgoing_event_queue for m in self.non_hook_modules]

    @property
    def module_priority_weights(self):
        if not self._module_priority_weights:
            # we subtract from six because lower priorities == higher weights
            priorities = [5] + [6 - m.priority for m in self.non_hook_modules]
            self._module_priority_weights = priorities
        return self._module_priority_weights

    async def get_incoming_event(self):
        for q in self.helpers.weighted_shuffle(self.incoming_queues, self.module_priority_weights):
            try:
                return q.get_nowait()
            except (asyncio.queues.QueueEmpty, AttributeError):
                continue
        raise asyncio.queues.QueueEmpty()

    def is_incoming_duplicate(self, event, add=False):
        """
        Calculate whether an event is a duplicate in the context of the module that emitted it
        This will return True if the event's parent module has raised the event before.
        """
        try:
            event_hash = event.module._outgoing_dedup_hash(event)
        except AttributeError:
            module_name = str(getattr(event, "module", ""))
            event_hash = hash((event, module_name))
        is_dup = event_hash in self.incoming_dup_tracker
        if add:
            self.incoming_dup_tracker.add(event_hash)
        suppress_dupes = getattr(event.module, "suppress_dupes", True)
        if suppress_dupes and is_dup:
            return True
        return False


class ScanEgress(InterceptModule):
    """
    This is always the last intercept module in the chain, responsible for executing and acting on the
    `abort_if` and `on_success_callback` functions.
    """

    watched_events = ["*"]
    # accept all events regardless of scope distance
    scope_distance_modifier = None
    _name = "_scan_egress"

    @property
    def priority(self):
        # we are the lowest priority
        return 99

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # track outgoing duplicates (for `accept_dupes` attribute of modules)
        self.outgoing_dup_tracker = set()

    async def handle_event(self, event, kwargs):
        abort_if = kwargs.pop("abort_if", None)
        on_success_callback = kwargs.pop("on_success_callback", None)

        # make event internal if it's above our configured report distance
        event_in_report_distance = event.scope_distance <= self.scan.scope_report_distance
        event_will_be_output = event.always_emit or event_in_report_distance
        if not event_will_be_output:
            log.debug(
                f"Making {event} internal because its scope_distance ({event.scope_distance}) > scope_report_distance ({self.scan.scope_report_distance})"
            )
            event.internal = True

        # if we discovered something interesting from an internal event,
        # make sure we preserve its chain of parents
        source = event.source
        if source.internal and ((not event.internal) or event._graph_important):
            source_in_report_distance = source.scope_distance <= self.scan.scope_report_distance
            if source_in_report_distance:
                source.internal = False
            if not source._graph_important:
                source._graph_important = True
                log.debug(f"Re-queuing internal event {source} with parent {event}")
                await self.emit_event(source)

        abort_result = False
        if callable(abort_if):
            async with self.scan._acatch(context=abort_if):
                abort_result = await self.scan.helpers.execute_sync_or_async(abort_if, event)
            msg = f"{event.module}: not raising event {event} due to custom criteria in abort_if()"
            with suppress(ValueError, TypeError):
                abort_result, reason = abort_result
                msg += f": {reason}"
            if abort_result:
                return False, msg

        # run success callback before distributing event (so it can add tags, etc.)
        if callable(on_success_callback):
            async with self.scan._acatch(context=on_success_callback):
                await self.scan.helpers.execute_sync_or_async(on_success_callback, event)

    async def forward_event(self, event, kwargs):
        """
        Queue event with modules
        """
        is_outgoing_duplicate = self.is_outgoing_duplicate(event)
        if is_outgoing_duplicate:
            self.verbose(f"{event.module}: Duplicate event: {event}")
        # absorb event into the word cloud if it's in scope
        if not is_outgoing_duplicate and -1 < event.scope_distance < 1:
            self.scan.word_cloud.absorb_event(event)

        for mod in self.scan.modules.values():
            # don't distribute events to hook modules
            if mod._hook:
                continue
            acceptable_dup = (not is_outgoing_duplicate) or mod.accept_dupes
            graph_important = mod._is_graph_important(event)
            if acceptable_dup or graph_important:
                await mod.queue_event(event)

    def is_outgoing_duplicate(self, event, add=False):
        """
        Calculate whether an event is a duplicate in the context of the whole scan,
        This will return True if the same event (irregardless of its source module) has been emitted before.

        TODO: Allow modules to use this for custom deduplication such as on a per-host or per-domain basis.
        """
        event_hash = hash(event)
        is_dup = event_hash in self.outgoing_dup_tracker
        if add:
            self.outgoing_dup_tracker.add(event_hash)
        return is_dup
