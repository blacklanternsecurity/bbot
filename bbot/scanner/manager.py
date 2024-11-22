import asyncio
from contextlib import suppress

from bbot.modules.base import BaseInterceptModule


class ScanIngress(BaseInterceptModule):
    """
    This is always the first intercept module in the chain, responsible for basic scope checks

    It has its own incoming queue, but will also pull events from modules' outgoing queues
    """

    watched_events = ["*"]
    # accept all events regardless of scope distance
    scope_distance_modifier = None
    _name = "_scan_ingress"
    _qsize = -1

    @property
    def priority(self):
        # we are the highest priority
        return -99

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._module_priority_weights = None
        self._non_intercept_modules = None
        # track incoming duplicates module-by-module (for `suppress_dupes` attribute of modules)
        self.incoming_dup_tracker = set()

    async def init_events(self, events=None):
        """
        Initializes events by seeding the scanner with target events and distributing them for further processing.

        Notes:
            - This method populates the event queue with initial target events.
            - It also marks the Scan object as finished with initialization by setting `_finished_init` to True.
        """
        if events is None:
            events = self.scan.target.seeds.events
        async with self.scan._acatch(self.init_events), self._task_counter.count(self.init_events):
            sorted_events = sorted(events, key=lambda e: len(e.data))
            for event in [self.scan.root_event] + sorted_events:
                event._dummy = False
                event.web_spider_distance = 0
                event.scan = self.scan
                if event.parent is None:
                    event.parent = self.scan.root_event
                if event.module is None:
                    event.module = self.scan._make_dummy_module(name="TARGET", _type="TARGET")
                if event != self.scan.root_event:
                    event.discovery_context = f"Scan {self.scan.name} seeded with " + "{event.type}: {event.data}"
                self.verbose(f"Target: {event}")
                await self.queue_event(event, {})
            await asyncio.sleep(0.1)
            self.scan._finished_init = True

    async def handle_event(self, event, **kwargs):
        # don't accept dummy events
        if event._dummy:
            return False, "cannot emit dummy event"

        # don't accept events with self as parent
        if not event.type == "SCAN":
            if event == event.get_parent():
                return False, "event's parent is itself"
            if not event.discovery_context:
                self.warning(f"Event {event} has no discovery context")

        # don't accept duplicates
        if self.is_incoming_duplicate(event, add=True):
            if not event._graph_important:
                return False, "event was already emitted by its module"
            else:
                self.debug(
                    f"Event {event} was already emitted by its module, but it's graph-important so it gets a pass"
                )

        # update event's scope distance based on its parent
        event.scope_distance = event.parent.scope_distance + 1

        # special handling of URL extensions
        url_extension = getattr(event, "url_extension", None)
        if url_extension is not None:
            if url_extension in self.scan.url_extension_httpx_only:
                event.add_tag("httpx-only")
                event._omit = True

            # blacklist by extension
            if url_extension in self.scan.url_extension_blacklist:
                self.debug(
                    f"Blacklisting {event} because its extension (.{url_extension}) is blacklisted in the config"
                )
                event.add_tag("blacklisted")

        # main scan blacklist
        event_blacklisted = self.scan.blacklisted(event)

        # reject all blacklisted events
        if event_blacklisted or "blacklisted" in event.tags:
            return False, "event is blacklisted"

        # Scope shepherding
        # here is where we make sure in-scope events are set to their proper scope distance
        if event.host:
            event_whitelisted = self.scan.whitelisted(event)
            if event_whitelisted:
                self.debug(f"Making {event} in-scope because its main host matches the scan target")
                event.scope_distance = 0

        # nerf event's priority if it's not in scope
        event.module_priority += event.scope_distance

    @property
    def non_intercept_modules(self):
        if self._non_intercept_modules is None:
            self._non_intercept_modules = [m for m in self.scan.modules.values() if not m._intercept]
        return self._non_intercept_modules

    @property
    def incoming_queues(self):
        queues = [self.incoming_event_queue] + [m.outgoing_event_queue for m in self.non_intercept_modules]
        return [q for q in queues if q is not False]

    @property
    def module_priority_weights(self):
        if not self._module_priority_weights:
            # we subtract from six because lower priorities == higher weights
            priorities = [5] + [6 - m.priority for m in self.non_intercept_modules]
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


class ScanEgress(BaseInterceptModule):
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

    async def handle_event(self, event, **kwargs):
        abort_if = kwargs.pop("abort_if", None)
        on_success_callback = kwargs.pop("on_success_callback", None)

        # omit certain event types
        if event.type in self.scan.omitted_event_types:
            if "target" in event.tags:
                self.debug(f"Allowing omitted event: {event} because it's a target")
            else:
                event._omit = True

        # make event internal if it's above our configured report distance
        event_in_report_distance = event.scope_distance <= self.scan.scope_report_distance
        event_will_be_output = event.always_emit or event_in_report_distance

        if not event_will_be_output:
            self.debug(
                f"Making {event} internal because its scope_distance ({event.scope_distance}) > scope_report_distance ({self.scan.scope_report_distance})"
            )
            event.internal = True

        if event.type in self.scan.omitted_event_types:
            self.debug(f"Omitting {event} because its type is omitted in the config")
            event._omit = True

        # if we discovered something interesting from an internal event,
        # make sure we preserve its chain of parents
        parent = event.parent
        event_is_graph_worthy = (not event.internal) or event._graph_important
        parent_is_graph_worthy = (not parent.internal) or parent._graph_important
        if event_is_graph_worthy and not parent_is_graph_worthy:
            parent_in_report_distance = parent.scope_distance <= self.scan.scope_report_distance
            if parent_in_report_distance:
                parent.internal = False
            if not parent._graph_important:
                parent._graph_important = True
                self.debug(f"Re-queuing internal event {parent} with parent {event} to prevent graph orphan")
                await self.emit_event(parent)

        if event._suppress_chain_dupes:
            for parent in event.get_parents():
                if parent == event:
                    return False, f"an identical parent {event} was found, and _suppress_chain_dupes=True"

        # custom callback - abort event emission it returns true
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
        # absorb event into the word cloud if it's in scope
        if -1 < event.scope_distance < 1:
            self.scan.word_cloud.absorb_event(event)

        for mod in self.scan.modules.values():
            # don't distribute events to intercept modules
            if not mod._intercept:
                await mod.queue_event(event)
