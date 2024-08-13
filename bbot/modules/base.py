import asyncio
import logging
import traceback
from sys import exc_info
from contextlib import suppress

from ..errors import ValidationError
from ..core.helpers.misc import get_size  # noqa
from ..core.helpers.async_helpers import TaskCounter, ShuffleQueue


class BaseModule:
    """The base class for all BBOT modules.

    Attributes:
        watched_events (List): Event types to watch.

        produced_events (List): Event types to produce.

        meta (Dict): Metadata about the module, such as whether authentication is required and a description.

        flags (List): Flags indicating the type of module (must have at least "safe" or "aggressive" and "passive" or "active").

        deps_modules (List): Other BBOT modules this module depends on. Empty list by default.

        deps_pip (List): Python dependencies to install via pip. Empty list by default.

        deps_apt (List): APT package dependencies to install. Empty list by default.

        deps_shell (List): Other dependencies installed via shell commands. Uses [ansible.builtin.shell](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/shell_module.html). Empty list by default.

        deps_ansible (List): Additional Ansible tasks for complex dependencies. Empty list by default.

        accept_dupes (bool): Whether to accept incoming duplicate events. Default is False.

        suppress_dupes (bool): Whether to suppress outgoing duplicate events. Default is True.

        per_host_only (bool): Limit the module to only scanning once per host. Default is False.

        per_hostport_only (bool): Limit the module to only scanning once per host:port. Default is False.

        per_domain_only (bool): Limit the module to only scanning once per domain. Default is False.

        scope_distance_modifier (int, None): Modifies scope distance acceptance for events. Default is 0.
            ```
            None == accept all events
            2 == accept events up to and including the scan's configured search distance plus two
            1 == accept events up to and including the scan's configured search distance plus one
            0 == (DEFAULT) accept events up to and including the scan's configured search distance
            ```

        target_only (bool): Accept only the initial target event(s). Default is False.

        in_scope_only (bool): Accept only explicitly in-scope events. Default is False.

        options (Dict): Customizable options for the module, e.g., {"api_key": ""}. Empty dict by default.

        options_desc (Dict): Descriptions for options, e.g., {"api_key": "API Key"}. Empty dict by default.

        module_threads (int): Maximum concurrent instances of handle_event() or handle_batch(). Default is 1.

        batch_size (int): Size of batches processed by handle_batch(). Default is 1.

        batch_wait (int): Seconds to wait before force-submitting a batch. Default is 10.

        failed_request_abort_threshold (int): Threshold for setting error state after failed HTTP requests (only takes effect when `request_with_fail_count()` is used. Default is 5.

        _preserve_graph (bool): When set to True, accept events that may be duplicates but are necessary for construction of complete graph. Typically only enabled for output modules that need to maintain full chains of events, e.g. `neo4j` and `json`. Default is False.

        _stats_exclude (bool): Whether to exclude this module from scan statistics. Default is False.

        _qsize (int): Outgoing queue size (0 for infinite). Default is 0.

        _priority (int): Priority level of events raised by this module, 1-5. Default is 3.

        _name (str): Module name, overridden automatically. Default is 'base'.

        _type (str): Module type, for differentiating between normal and output modules. Default is 'scan'.
    """

    watched_events = []
    produced_events = []
    meta = {"auth_required": False, "description": "Base module"}
    flags = []
    options = {}
    options_desc = {}

    deps_modules = []
    deps_pip = []
    deps_apt = []
    deps_shell = []
    deps_ansible = []

    accept_dupes = False
    suppress_dupes = True
    per_host_only = False
    per_hostport_only = False
    per_domain_only = False
    scope_distance_modifier = 0
    target_only = False
    in_scope_only = False

    _module_threads = 1
    _batch_size = 1
    batch_wait = 10
    failed_request_abort_threshold = 5

    default_discovery_context = "{module} discovered {event.type}: {event.data}"

    _preserve_graph = False
    _stats_exclude = False
    _qsize = 1000
    _priority = 3
    _name = "base"
    _type = "scan"
    _intercept = False
    _shuffle_incoming_queue = True

    def __init__(self, scan):
        """Initializes a module instance.

        Args:
            scan: The BBOT scan object associated with this module instance.

        Attributes:
            scan: The scan object associated with this module.

            errored (bool): Whether the module has errored out. Default is False.
        """
        self.scan = scan
        self.errored = False
        self._log = None
        self._incoming_event_queue = None
        self._outgoing_event_queue = None
        # track incoming events to prevent unwanted duplicates
        self._incoming_dup_tracker = set()
        # tracks which subprocesses are running under this module
        self._proc_tracker = set()
        # seconds since we've submitted a batch
        self._last_submitted_batch = None
        # additional callbacks to be executed alongside self.cleanup()
        self.cleanup_callbacks = []
        self._cleanedup = False
        self._watched_events = None

        self._task_counter = TaskCounter()

        # string constant
        self._custom_filter_criteria_msg = "it did not meet custom filter criteria"

        # track number of failures (for .request_with_fail_count())
        self._request_failures = 0

        self._tasks = []
        self._event_received = asyncio.Condition()
        self._event_queued = asyncio.Condition()

        # used for optional "per host" tracking
        self._per_host_tracker = set()

    async def setup(self):
        """
        Performs one-time setup tasks for the module.

        This method is responsible for preparing the module for its operation, which may include tasks
        such as downloading necessary resources, validating configuration parameters, or other preliminary
        checks.

        Returns:
            tuple:
                - bool or None: A status indicating the outcome of the setup process. Returns `True` if
                the setup was successful, `None` for a soft-fail where the module setup did not succeed
                but the scan will continue with the module disabled, and `False` for a hard-fail where
                the setup failure causes the scan to abort.
                - str, optional: A reason for the setup failure, provided only when the setup does not
                succeed (i.e., returns `None` or `False`).

        Examples:
            >>> async def setup(self):
            >>>     if not self.config.get("api_key"):
            >>>         # Soft-fail: Configuration missing an API key
            >>>         return None, "No API key specified"

            >>> async def setup(self):
            >>>     try:
            >>>         wordlist = await self.helpers.wordlist("https://raw.githubusercontent.com/user/wordlist.txt")
            >>>     except WordlistError as e:
            >>>         # Hard-fail: Error retrieving wordlist
            >>>         return False, f"Error retrieving wordlist: {e}"

            >>> async def setup(self):
            >>>     self.timeout = self.config.get("timeout", 5)
            >>>     # Success: Setup completed without issues
            >>>     return True
        """

        return True

    async def handle_event(self, event):
        """Asynchronously handles incoming events that the module is configured to watch.

        This method is automatically invoked when an event that matches any in `watched_events` is encountered during a scan. Override this method to implement custom event-handling logic for your module.

        Args:
            event (Event): The event object containing details about the incoming event.

        Note:
            This method should be overridden if the `batch_size` attribute of the module is set to 1.

        Returns:
            None
        """
        pass

    async def handle_batch(self, *events):
        """Handles incoming events in batches for optimized processing.

        This method is automatically called when multiple events that match any in `watched_events` are encountered and the `batch_size` attribute is set to a value greater than 1. Override this method to implement custom batch event-handling logic for your module.

        Args:
            *events (Event): A variable number of Event objects to be processed in a batch.

        Note:
            This method should be overridden if the `batch_size` attribute of the module is set to a value greater than 1.

        Returns:
            None
        """
        pass

    async def filter_event(self, event):
        """Asynchronously filters incoming events based on custom criteria.

        Override this method for more granular control over which events are accepted by your module. This method is called automatically before `handle_event()` for each incoming event that matches any in `watched_events`.

        Args:
            event (Event): The incoming Event object to be filtered.

        Returns:
            tuple: A 2-tuple where the first value is a bool indicating whether the event should be accepted, and the second value is a string explaining the reason for its acceptance or rejection. By default, returns `(True, None)` to indicate acceptance without reason.

        Note:
            This method should be overridden if the module requires custom logic for event filtering.
        """
        return True

    async def finish(self):
        """Asynchronously performs final tasks as the scan nears completion.

        This method can be overridden to execute any necessary finalization logic. For example, if the module relies on a word cloud, you might wait for the scan to finish to ensure the word cloud is most complete before running an operation.

        Returns:
            None

        Warnings:
            This method may be called multiple times since it can raise events, which may re-trigger the "finish" phase of the scan. Optional to override.
        """
        return

    async def report(self):
        """Asynchronously executes a final task after the scan is complete but before cleanup.

        This method can be overridden to aggregate data and raise summary events at the end of the scan.

        Returns:
            None

        Note:
            This method is called only once per scan.
        """
        return

    async def cleanup(self):
        """Asynchronously performs final cleanup operations after the scan is complete.

        This method can be overridden to implement custom cleanup logic. It is called only once per scan and may not raise events.

        Returns:
            None

        Note:
            This method is called only once per scan and may not raise events.
        """
        return

    async def require_api_key(self):
        """
        Asynchronously checks if an API key is required and valid.

        Args:
            None

        Returns:
            bool or tuple: Returns True if API key is valid and ready.
                          Returns a tuple (None, "error message") otherwise.

        Notes:
            - Fetches the API key from the configuration.
            - Calls the 'ping()' method to test API accessibility.
            - Sets the API key readiness status accordingly.
        """
        self.api_key = self.config.get("api_key", "")
        if self.auth_secret:
            try:
                await self.ping()
                self.hugesuccess(f"API is ready")
                return True
            except Exception as e:
                return None, f"Error with API ({str(e).strip()})"
        else:
            return None, "No API key set"

    async def ping(self):
        """Asynchronously checks the health of the configured API.

        This method is used in conjunction with require_api_key() to verify that the API is not just configured, but also responsive. This method should include an assert statement to validate the API's health, typically by making a test request to a known endpoint.

        Example Usage:
            In your implementation, if the API has a "/ping" endpoint:
            async def ping(self):
                r = await self.request_with_fail_count(f"{self.base_url}/ping")
                resp_content = getattr(r, "text", "")
                assert getattr(r, "status_code", 0) == 200, resp_content

        Returns:
            None

        Raises:
            AssertionError: If the API does not respond as expected.
        """
        return

    @property
    def batch_size(self):
        batch_size = self.config.get("batch_size", None)
        # only allow overriding the batch size if its default value is greater than 1
        # this prevents modules from being accidentally neutered by an incorrect batch_size setting
        if batch_size is None or self._batch_size == 1:
            batch_size = self._batch_size
        return batch_size

    @property
    def module_threads(self):
        module_threads = self.config.get("module_threads", None)
        if module_threads is None:
            module_threads = self._module_threads
        return module_threads

    @property
    def auth_secret(self):
        """Indicates if the module is properly configured for authentication.

        This read-only property should be used to check whether all necessary attributes (e.g., API keys, tokens, etc.) are configured to perform authenticated requests in the module. Commonly used in setup or initialization steps.

        Returns:
            bool: True if the module is properly configured for authentication, otherwise False.
        """
        return getattr(self, "api_key", "")

    def get_watched_events(self):
        """Retrieve the set of events that the module is interested in observing.

        Override this method if the set of events the module should watch needs to be determined dynamically, e.g., based on configuration options or other runtime conditions.

        Returns:
            set: The set of event types that this module will handle.
        """
        if self._watched_events is None:
            self._watched_events = set(self.watched_events)
        return self._watched_events

    async def _handle_batch(self):
        """
        Asynchronously handles a batch of events in the module.

        Args:
            None

        Returns:
            bool: True if events were submitted for processing, False otherwise.

        Notes:
            - The method is wrapped in a task counter to monitor asynchronous operations.
            - Checks if there are any events in the incoming queue and module is not in an error state.
            - Invokes '_events_waiting()' to fetch a batch of events.
            - Calls the module's 'handle_batch()' method to process these events.
            - If a "FINISHED" event is found, invokes 'finish()' method of the module.
        """
        finish = False
        async with self._task_counter.count(f"{self.name}.handle_batch()") as counter:
            submitted = False
            if self.batch_size <= 1:
                return
            if self.num_incoming_events > 0:
                events, finish = await self._events_waiting()
                if events and not self.errored:
                    counter.n = len(events)
                    self.verbose(f"Handling batch of {len(events):,} events")
                    submitted = True
                    async with self.scan._acatch(f"{self.name}.handle_batch()"):
                        await self.handle_batch(*events)
                    self.verbose(f"Finished handling batch of {len(events):,} events")
        if finish:
            context = f"{self.name}.finish()"
            async with self.scan._acatch(context), self._task_counter.count(context):
                await self.finish()
        return submitted

    def make_event(self, *args, **kwargs):
        """Create an event for the scan.

        Raises a validation error if the event could not be created, unless raise_error is set to False.

        Args:
            *args: Positional arguments to be passed to the scan's make_event method.
            **kwargs: Keyword arguments to be passed to the scan's make_event method.
            raise_error (bool, optional): Whether to raise a validation error if the event could not be created. Defaults to False.

        Examples:
            >>> new_event = self.make_event("1.2.3.4", parent=event)
            >>> await self.emit_event(new_event)

        Returns:
            Event or None: The created event, or None if a validation error occurred and raise_error was False.

        Raises:
            ValidationError: If the event could not be validated and raise_error is True.
        """
        raise_error = kwargs.pop("raise_error", False)
        module = kwargs.pop("module", None)
        if module is None:
            if (not args) or getattr(args[0], "module", None) is None:
                kwargs["module"] = self
        try:
            event = self.scan.make_event(*args, **kwargs)
        except ValidationError as e:
            if raise_error:
                raise
            self.warning(f"{e}")
            return
        return event

    async def emit_event(self, *args, **kwargs):
        """Emit an event to the event queue and distribute it to interested modules.

        This is how modules "return" data.

        The method first creates an event object by calling `self.make_event()` with the provided arguments.
        Then, the event is queued for outgoing distribution using `self.queue_outgoing_event()`.

        Args:
            *args: Positional arguments to be passed to `self.make_event()` for event creation.
            **kwargs: Keyword arguments to be passed for event creation or configuration of the emit action.
                ```markdown
                - on_success_callback: Optional callback function to execute upon successful event emission.
                - abort_if: Optional condition under which the event emission should be aborted.
                - quick: Optional flag to indicate whether the event should be processed quickly.
                ```

        Examples:
            >>> await self.emit_event("www.evilcorp.com", parent=event, tags=["affiliate"])

            >>> new_event = self.make_event("1.2.3.4", parent=event)
            >>> await self.emit_event(new_event)

        Returns:
            None

        Raises:
            ValidationError: If the event cannot be validated (handled in `self.make_event()`).
        """
        event_kwargs = dict(kwargs)
        emit_kwargs = {}
        for o in ("on_success_callback", "abort_if", "quick"):
            v = event_kwargs.pop(o, None)
            if v is not None:
                emit_kwargs[o] = v
        event = self.make_event(*args, **event_kwargs)
        if event:
            await self.queue_outgoing_event(event, **emit_kwargs)
        return event

    async def _events_waiting(self, batch_size=None):
        """
        Asynchronously fetches events from the incoming_event_queue, up to a specified batch size.

        Args:
            None

        Returns:
            tuple: A tuple containing two elements:
                - events (list): A list of acceptable events from the queue.
                - finish (bool): A flag indicating if a "FINISHED" event is encountered.

        Notes:
            - The method pulls events from incoming_event_queue using 'get_nowait()'.
            - Events go through '_event_postcheck()' for validation.
            - "FINISHED" events are handled differently and the finish flag is set to True.
            - If the queue is empty or the batch size is reached, the loop breaks.
        """
        if batch_size is None:
            batch_size = self.batch_size
        events = []
        finish = False
        while self.incoming_event_queue:
            if batch_size != -1 and len(events) > self.batch_size:
                break
            try:
                event = self.incoming_event_queue.get_nowait()
                self.debug(f"Got {event} from {getattr(event, 'module', 'unknown_module')}")
                acceptable, reason = await self._event_postcheck(event)
                if acceptable:
                    if event.type == "FINISHED":
                        finish = True
                    else:
                        events.append(event)
                        self.scan.stats.event_consumed(event, self)
                elif reason:
                    self.debug(f"Not accepting {event} because {reason}")
            except asyncio.queues.QueueEmpty:
                break
        return events, finish

    @property
    def num_incoming_events(self):
        ret = 0
        if self.incoming_event_queue is not False:
            ret = self.incoming_event_queue.qsize()
        return ret

    def start(self):
        self._tasks = [
            asyncio.create_task(self._worker(), name=f"{self.scan.name}.{self.name}._worker()")
            for _ in range(self.module_threads)
        ]

    async def _setup(self):
        """
        Asynchronously sets up the module by invoking its 'setup()' method.

        This method catches exceptions during setup, sets the module's error state if necessary, and determines the
        status code based on the result of the setup process.

        Args:
            None

        Returns:
            tuple: A tuple containing the module's name, status (True for success, False for hard-fail, None for soft-fail),
            and an optional status message.

        Raises:
            Exception: Captured exceptions from the 'setup()' method are logged, but not propagated.

        Notes:
            - The 'setup()' method can return either a simple boolean status or a tuple of status and message.
            - A WordlistError exception triggers a soft-fail status.
            - The debug log will contain setup status information for the module.
        """
        status_codes = {False: "hard-fail", None: "soft-fail", True: "success"}

        status = False
        self.debug(f"Setting up module {self.name}")
        try:
            result = await self.setup()
            if type(result) == tuple and len(result) == 2:
                status, msg = result
            else:
                status = result
                msg = status_codes[status]
            self.debug(f"Finished setting up module {self.name}")
        except Exception as e:
            self.set_error_state(f"Unexpected error during module setup: {e}", critical=True)
            msg = f"{e}"
            self.trace()
        return self, status, str(msg)

    async def _worker(self):
        """
        The core worker loop for the module, responsible for handling events from the incoming event queue.

        This method is a coroutine and is run asynchronously. Multiple instances can run simultaneously based on
        the 'module_threads' configuration. The worker dequeues events from 'incoming_event_queue', performs
        necessary prechecks, and passes the event to the appropriate handler function.

        Args:
            None

        Returns:
            None

        Raises:
            asyncio.CancelledError: If the worker is cancelled during its operation.

        Notes:
            - The worker is sensitive to the 'stopping' flag of the scan. It will terminate if this flag is set.
            - The worker handles backpressure by pausing when the outgoing event queue is full.
            - Batch processing is supported and is activated when 'batch_size' > 1.
            - Each event is subject to a post-check via '_event_postcheck()' to decide whether it should be handled.
            - Special 'FINISHED' events trigger the 'finish()' method of the module.
        """
        async with self.scan._acatch(context=self._worker, unhandled_is_critical=True):
            try:
                while not self.scan.stopping and not self.errored:
                    # hold the reigns if our outgoing queue is full
                    if self._qsize > 0 and self.outgoing_event_queue.qsize() >= self._qsize:
                        await asyncio.sleep(0.1)
                        continue

                    if self.batch_size > 1:
                        submitted = await self._handle_batch()
                        if not submitted:
                            async with self._event_received:
                                await self._event_received.wait()

                    else:
                        try:
                            if self.incoming_event_queue is not False:
                                event = await self.incoming_event_queue.get()
                            else:
                                self.debug(f"Event queue is in bad state")
                                break
                        except asyncio.queues.QueueEmpty:
                            continue
                        self.debug(f"Got {event} from {getattr(event, 'module', 'unknown_module')}")
                        async with self._task_counter.count(f"event_postcheck({event})"):
                            acceptable, reason = await self._event_postcheck(event)
                        if acceptable:
                            if event.type == "FINISHED":
                                context = f"{self.name}.finish()"
                                async with self.scan._acatch(context), self._task_counter.count(context):
                                    await self.finish()
                            else:
                                context = f"{self.name}.handle_event({event})"
                                self.scan.stats.event_consumed(event, self)
                                self.debug(f"Handling {event}")
                                async with self.scan._acatch(context), self._task_counter.count(context):
                                    await self.handle_event(event)
                                self.debug(f"Finished handling {event}")
                        else:
                            self.debug(f"Not accepting {event} because {reason}")
            except asyncio.CancelledError:
                # this trace was used for debugging leaked CancelledErrors from inside httpx
                # self.log.trace("Worker cancelled")
                raise
            except BaseException as e:
                if self.helpers.in_exception_chain(e, (KeyboardInterrupt,)):
                    self.scan.stop()
                else:
                    self.error(f"Critical failure in module {self.name}: {e}")
                    self.error(traceback.format_exc())
        self.log.trace(f"Worker stopped")

    @property
    def max_scope_distance(self):
        if self.in_scope_only or self.target_only:
            return 0
        if self.scope_distance_modifier is None:
            return 999
        return max(0, self.scan.scope_search_distance + self.scope_distance_modifier)

    def _event_precheck(self, event):
        """
        Pre-checks an event to determine if it should be accepted by the module for queuing.

        This method is called when an event is about to be enqueued into the module's incoming event queue.
        It applies various filters such as special signal event types, module error state, watched event types, and more
        to decide whether or not the event should be enqueued.

        Args:
            event (Event): The event object to check.

        Returns:
            tuple: A tuple (bool, str) where the bool indicates if the event should be accepted, and the str gives the reason.

        Examples:
            >>> result, reason = self._event_precheck(event)
            >>> if result:
            ...     self.incoming_event_queue.put_nowait(event)
            ... else:
            ...     self.debug(f"Not accepting {event} because {reason}")

        Notes:
            - The method considers special signal event types like "FINISHED".
            - Checks whether the module is in an error state.
            - Checks if the event type matches the types this module is interested in (`watched_events`).
            - Checks for events tagged as 'target' if the module has `target_only` flag set.
            - Applies specific filtering based on event type and module name.
        """

        # special signal event types
        if event.type in ("FINISHED",):
            return True, "its type is FINISHED"
        if self.errored:
            return False, f"module is in error state"
        # exclude non-watched types
        if not any(t in self.get_watched_events() for t in ("*", event.type)):
            return False, "its type is not in watched_events"
        if self.target_only:
            if "target" not in event.tags:
                return False, "it did not meet target_only filter criteria"

        # exclude certain URLs (e.g. javascript):
        # TODO: revisit this after httpx rework
        if event.type.startswith("URL") and self.name != "httpx" and "httpx-only" in event.tags:
            return False, "its extension was listed in url_extension_httpx_only"

        return True, "precheck succeeded"

    async def _event_postcheck(self, event):
        """
        A simple wrapper for dup tracking
        """
        # special exception for "FINISHED" event
        if event.type in ("FINISHED",):
            return True, ""
        acceptable, reason = await self._event_postcheck_inner(event)
        if acceptable:
            # check duplicates
            is_incoming_duplicate, reason = self.is_incoming_duplicate(event, add=True)
            if is_incoming_duplicate and not self.accept_dupes:
                return False, f"module has already seen it" + (f" ({reason})" if reason else "")

        return acceptable, reason

    async def _event_postcheck_inner(self, event):
        """
        Post-checks an event to determine if it should be accepted by the module for handling.

        This method is called when an event is dequeued from the module's incoming event queue, right before it is actually processed.
        It applies various filters such as scope, custom filtering logic, and per-host tracking to decide the event's fate.

        Args:
            event (Event): The event object to check.

        Returns:
            tuple: A tuple (bool, str) where the bool indicates if the event should be accepted, and the str gives the reason.

        Notes:
            - Override the `filter_event` method for custom filtering logic.
            - This method also maintains host-based tracking when the `per_host_only` or similar flags are set.
            - The method will also update event production stats for output modules.
        """
        # force-output certain events to the graph
        if self._is_graph_important(event):
            return True, "event is critical to the graph"

        # check scope distance
        filter_result, reason = self._scope_distance_check(event)
        if not filter_result:
            return filter_result, reason

        # custom filtering
        async with self.scan._acatch(context=self.filter_event):
            try:
                filter_result = await self.filter_event(event)
            except Exception as e:
                msg = f"Unhandled exception in {self.name}.filter_event({event}): {e}"
                self.error(msg)
                return False, msg
            msg = str(self._custom_filter_criteria_msg)
            with suppress(ValueError, TypeError):
                filter_result, reason = filter_result
                msg += f": {reason}"
            if not filter_result:
                return False, msg

        self.debug(f"{event} passed post-check")
        return True, ""

    def _scope_distance_check(self, event):
        if self.in_scope_only:
            if event.scope_distance > 0:
                return False, "it did not meet in_scope_only filter criteria"
        if self.scope_distance_modifier is not None:
            if event.scope_distance < 0:
                return False, f"its scope_distance ({event.scope_distance}) is invalid."
            elif event.scope_distance > self.max_scope_distance:
                return (
                    False,
                    f"its scope_distance ({event.scope_distance}) exceeds the maximum allowed by the scan ({self.scan.scope_search_distance}) + the module ({self.scope_distance_modifier}) == {self.max_scope_distance}",
                )
        return True, ""

    async def _cleanup(self):
        if not self._cleanedup:
            self._cleanedup = True
            for callback in [self.cleanup] + self.cleanup_callbacks:
                context = f"{self.name}.cleanup()"
                if callable(callback):
                    async with self.scan._acatch(context), self._task_counter.count(context):
                        await self.helpers.execute_sync_or_async(callback)

    async def queue_event(self, event):
        """
        Asynchronously queues an incoming event to the module's event queue for further processing.

        The function performs an initial check to see if the event is acceptable for queuing.
        If the event passes the check, it is put into the `incoming_event_queue`.

        Args:
            event: The event object to be queued.

        Returns:
            None: The function doesn't return anything but modifies the state of the `incoming_event_queue`.

        Examples:
            >>> await self.queue_event(some_event)

        Raises:
            AttributeError: If the module is not in an acceptable state to queue incoming events.
        """
        async with self._task_counter.count("queue_event()", _log=False):
            if self.incoming_event_queue is False:
                self.debug(f"Not in an acceptable state to queue incoming event")
                return
            acceptable, reason = self._event_precheck(event)
            if not acceptable:
                if reason and reason != "its type is not in watched_events":
                    self.debug(f"Not queueing {event} because {reason}")
                return
            else:
                self.debug(f"Queueing {event} because {reason}")
            try:
                self.incoming_event_queue.put_nowait(event)
                async with self._event_received:
                    self._event_received.notify()
                if event.type != "FINISHED":
                    self.scan._new_activity = True
            except AttributeError:
                self.debug(f"Not in an acceptable state to queue incoming event")

    async def queue_outgoing_event(self, event, **kwargs):
        """
        Queues an outgoing event to the module's outgoing event queue for further processing.

        The function attempts to put the event into the `outgoing_event_queue` immediately.
        If it's not possible due to the current state of the module, an AttributeError is raised, and a debug log is generated.

        Args:
            event: The event object to be queued.
            **kwargs: Additional keyword arguments to be associated with the event.

        Returns:
            None: The function doesn't return anything but modifies the state of the `outgoing_event_queue`.

        Examples:
            >>> self.queue_outgoing_event(some_outgoing_event, abort_if=lambda e: "unresolved" in e.tags)

        Raises:
            AttributeError: If the module is not in an acceptable state to queue outgoing events.
        """
        try:
            await self.outgoing_event_queue.put((event, kwargs))
        except AttributeError:
            self.debug(f"Not in an acceptable state to queue outgoing event")

    def set_error_state(self, message=None, clear_outgoing_queue=False, critical=False):
        """
        Puts the module into an errored state where it cannot accept new events. Optionally logs a warning message.

        The function sets the module's `errored` attribute to True and logs a warning with the optional message.
        It also clears the incoming event queue to prevent further processing and updates its status to False.

        Args:
            message (str, optional): Additional message to be logged along with the warning.

        Returns:
            None: The function doesn't return anything but updates the `errored` state and clears the incoming event queue.

        Examples:
            >>> self.set_error_state()
            >>> self.set_error_state("Failed to connect to the server")

        Notes:
            - The function sets `self._incoming_event_queue` to False to prevent its further use.
            - If the module was already in an errored state, the function will not reset the error state or the queue.
        """
        if not self.errored:
            log_msg = "Setting error state"
            if message is not None:
                log_msg += f": {message}"
            if critical:
                log_fn = self.error
            else:
                log_fn = self.warning
            log_fn(log_msg)
            self.errored = True
            # clear incoming queue
            if self.incoming_event_queue is not False:
                self.debug(f"Emptying event_queue")
                with suppress(asyncio.queues.QueueEmpty):
                    while 1:
                        self.incoming_event_queue.get_nowait()
                # set queue to None to prevent its use
                # if there are leftover objects in the queue, the scan will hang.
                self._incoming_event_queue = False

            if clear_outgoing_queue:
                with suppress(asyncio.queues.QueueEmpty):
                    while 1:
                        self.outgoing_event_queue.get_nowait()

    def is_incoming_duplicate(self, event, add=False):
        if event.type in ("FINISHED",):
            return False, ""
        reason = ""
        try:
            event_hash = self._incoming_dedup_hash(event)
        except Exception as e:
            msg = f"Unhandled exception in {self.name}._incoming_dedup_hash({event}): {e}"
            self.error(msg)
            return True, msg
        with suppress(TypeError, ValueError):
            event_hash, reason = event_hash
        is_dup = event_hash in self._incoming_dup_tracker
        if add:
            self._incoming_dup_tracker.add(event_hash)
        return is_dup, reason

    def _incoming_dedup_hash(self, event):
        """
        Determines the criteria for what is considered to be a duplicate event if `accept_dupes` is False.
        """
        if self.per_host_only:
            return self.get_per_host_hash(event), "per_host_only=True"
        if self.per_hostport_only:
            return self.get_per_hostport_hash(event), "per_hostport_only=True"
        elif self.per_domain_only:
            return self.get_per_domain_hash(event), "per_domain_only=True"
        return hash(event), ""

    def _outgoing_dedup_hash(self, event):
        """
        Determines the criteria for what is considered to be a duplicate event if `suppress_dupes` is True.
        """
        return hash((event, self.name))

    def get_per_host_hash(self, event):
        """
        Computes a per-host hash value for a given event. This method may be optionally overridden in subclasses.

        The function uses the event's `host` to create a string to be hashed.

        Args:
            event (Event): The event object containing host information.

        Returns:
            int: The hash value computed for the host.

        Examples:
            >>> event = self.make_event("https://example.com:8443")
            >>> self.get_per_host_hash(event)
        """
        return hash(event.host)

    def get_per_hostport_hash(self, event):
        """
        Computes a per-host:port hash value for a given event. This method may be optionally overridden in subclasses.

        The function uses the event's `host`, `port`, and `scheme` (for URLs) to create a string to be hashed.
        The hash value is used for distinguishing events related to the same host.

        Args:
            event (Event): The event object containing host, port, or parsed URL information.

        Returns:
            int: The hash value computed for the host.

        Examples:
            >>> event = self.make_event("https://example.com:8443")
            >>> self.get_per_hostport_hash(event)
        """
        parsed = getattr(event, "parsed_url", None)
        if parsed is None:
            to_hash = self.helpers.make_netloc(event.host, event.port)
        else:
            to_hash = f"{parsed.scheme}://{parsed.netloc}/"
        return hash(to_hash)

    def get_per_domain_hash(self, event):
        """
        Computes a per-domain hash value for a given event. This method may be optionally overridden in subclasses.

        Events with the same root domain will receive the same hash value.

        Args:
            event (Event): The event object containing host, port, or parsed URL information.

        Returns:
            int: The hash value computed for the domain.

        Examples:
            >>> event = self.make_event("https://www.example.com:8443")
            >>> self.get_per_domain_hash(event)
        """
        _, domain = self.helpers.split_domain(event.host)
        return hash(domain)

    @property
    def name(self):
        return str(self._name)

    @property
    def helpers(self):
        return self.scan.helpers

    @property
    def status(self):
        """
        Provides the current status of the module as a dictionary.

        The dictionary contains the following keys:
            - 'events': A sub-dictionary with 'incoming' and 'outgoing' keys, representing the number of events in the respective queues.
            - 'tasks': The current value of the task counter.
            - 'errored': A boolean value indicating if the module is in an error state.
            - 'running': A boolean value indicating if the module is currently processing data.

        Returns:
            dict: A dictionary containing the current status of the module.

        Examples:
            >>> self.status
            {'events': {'incoming': 5, 'outgoing': 2}, 'tasks': 3, 'errored': False, 'running': True}
        """
        status = {
            "events": {"incoming": self.num_incoming_events, "outgoing": self.outgoing_event_queue.qsize()},
            "tasks": self._task_counter.value,
            "errored": self.errored,
        }
        status["running"] = self.running
        return status

    @property
    def running(self):
        """Property indicating whether the module is currently processing data.

        This property checks if the task counter (`self._task_counter.value`) is greater than zero,
        indicating that there are ongoing tasks in the module.

        Returns:
            bool: True if the module is currently processing data, False otherwise.
        """
        return self._task_counter.value > 0

    @property
    def finished(self):
        """Property indicating whether the module has finished processing.

        This property checks three conditions to determine if the module is finished:
        1. The module is not currently running (`self.running` is False).
        2. The number of incoming events in the queue is zero or less (`self.num_incoming_events <= 0`).
        3. The number of outgoing events in the queue is zero or less (`self.outgoing_event_queue.qsize() <= 0`).

        Returns:
            bool: True if the module has finished processing, False otherwise.
        """
        return not self.running and self.num_incoming_events <= 0 and self.outgoing_event_queue.qsize() <= 0

    async def run_process(self, *args, **kwargs):
        kwargs["_proc_tracker"] = self._proc_tracker
        return await self.helpers.run(*args, **kwargs)

    async def run_process_live(self, *args, **kwargs):
        kwargs["_proc_tracker"] = self._proc_tracker
        async for line in self.helpers.run_live(*args, **kwargs):
            yield line

    async def request_with_fail_count(self, *args, **kwargs):
        """Asynchronously perform an HTTP request while keeping track of consecutive failures.

        This function wraps the `self.helpers.request` method, incrementing a failure counter if
        the request returns None. When the failure counter exceeds `self.failed_request_abort_threshold`,
        the module is set to an error state.

        Args:
            *args: Positional arguments to pass to `self.helpers.request`.
            **kwargs: Keyword arguments to pass to `self.helpers.request`.

        Returns:
            Any: The response object or None if the request failed.

        Raises:
            None: Sets the module to an error state when the failure threshold is reached.
        """
        r = await self.helpers.request(*args, **kwargs)
        if r is None:
            self._request_failures += 1
        else:
            self._request_failures = 0
        if self._request_failures >= self.failed_request_abort_threshold:
            self.set_error_state(f"Setting error state due to {self._request_failures:,} failed HTTP requests")
        return r

    @property
    def preset(self):
        return self.scan.preset

    @property
    def config(self):
        """Property that provides easy access to the module's configuration in the scan's config.

        This property serves as a shortcut to retrieve the module-specific configuration from
        `self.scan.config`. If no configuration is found for this module, an empty dictionary is returned.

        Returns:
            dict: The configuration dictionary specific to this module.
        """
        config = self.scan.config.get("modules", {}).get(self.name, {})
        if config is None:
            config = {}
        return config

    @property
    def incoming_event_queue(self):
        if self._incoming_event_queue is None:
            if self._shuffle_incoming_queue:
                self._incoming_event_queue = ShuffleQueue()
            else:
                self._incoming_event_queue = asyncio.Queue()
        return self._incoming_event_queue

    @property
    def outgoing_event_queue(self):
        if self._outgoing_event_queue is None:
            self._outgoing_event_queue = ShuffleQueue(self._qsize)
        return self._outgoing_event_queue

    @property
    def priority(self):
        """
        Gets the priority level of the module as an integer.

        The priority level is constrained to be between 1 and 5, inclusive.
        A lower value indicates a higher priority.

        Returns:
            int: The priority level of the module, constrained between 1 and 5.

        Examples:
            >>> self.priority
            3
        """
        return int(max(1, min(5, self._priority)))

    @property
    def auth_required(self):
        return self.meta.get("auth_required", False)

    @property
    def http_timeout(self):
        """
        Convenience shortcut to `http_timeout` in the config
        """
        return self.scan.web_config.get("http_timeout", 10)

    @property
    def log(self):
        if getattr(self, "_log", None) is None:
            self._log = logging.getLogger(f"bbot.modules.{self.name}")
        return self._log

    @property
    def memory_usage(self):
        """Property that calculates the current memory usage of the module in bytes.

        This property uses the `get_size` function to estimate the memory consumption
        of the module object. The depth of the object graph traversal is limited to 3 levels
        to avoid performance issues. Commonly shared objects like `self.scan`, `self.helpers`,
        are excluded from the calculation to prevent double-counting.

        Returns:
            int: The estimated memory usage of the module in bytes.
        """
        seen = {self.scan, self.helpers, self.log}  # noqa
        return get_size(self, max_depth=3, seen=seen)

    def __str__(self):
        return self.name

    def log_table(self, *args, **kwargs):
        """Logs a table to the console and optionally writes it to a file.

        This function generates a table using `self.helpers.make_table`, then logs each line
        of the table as an info-level log. If a table_name is provided, it also writes the table to a file.

        Args:
            *args: Variable length argument list to be passed to `self.helpers.make_table`.
            **kwargs: Arbitrary keyword arguments. If 'table_name' is specified, the table will be written to a file.

        Returns:
            str: The generated table as a string.

        Examples:
            >>> self.log_table(['Header1', 'Header2'], [['row1col1', 'row1col2'], ['row2col1', 'row2col2']], table_name="my_table")
        """
        table_name = kwargs.pop("table_name", None)
        max_log_entries = kwargs.pop("max_log_entries", None)
        table = self.helpers.make_table(*args, **kwargs)
        lines_logged = 0
        for line in table.splitlines():
            if max_log_entries is not None and lines_logged > max_log_entries:
                break
            self.info(line)
            lines_logged += 1
        if table_name is not None:
            date = self.helpers.make_date()
            filename = self.scan.home / f"{self.helpers.tagify(table_name)}-table-{date}.txt"
            with open(filename, "w") as f:
                f.write(table)
            self.verbose(f"Wrote {table_name} to {filename}")
        return table

    def _is_graph_important(self, event):
        return self.preserve_graph and getattr(event, "_graph_important", False) and not getattr(event, "_omit", False)

    @property
    def preserve_graph(self):
        preserve_graph = self.config.get("preserve_graph", None)
        if preserve_graph is None:
            preserve_graph = self._preserve_graph
        return preserve_graph

    def debug(self, *args, trace=False, **kwargs):
        """Logs debug messages and optionally the stack trace of the most recent exception.

        Args:
            *args: Variable-length argument list to pass to the logger.
            trace (bool, optional): Whether to log the stack trace of the most recently caught exception. Defaults to False.
            **kwargs: Arbitrary keyword arguments to pass to the logger.

        Examples:
            >>> self.debug("This is a debug message")
            >>> self.debug("This is a debug message with a trace", trace=True)
        """
        self.log.debug(*args, extra={"scan_id": self.scan.id}, **kwargs)
        if trace:
            self.trace()

    def verbose(self, *args, trace=False, **kwargs):
        """Logs messages and optionally the stack trace of the most recent exception.

        Args:
            *args: Variable-length argument list to pass to the logger.
            trace (bool, optional): Whether to log the stack trace of the most recently caught exception. Defaults to False.
            **kwargs: Arbitrary keyword arguments to pass to the logger.

        Examples:
            >>> self.verbose("This is a verbose message")
            >>> self.verbose("This is a verbose message with a trace", trace=True)
        """
        self.log.verbose(*args, extra={"scan_id": self.scan.id}, **kwargs)
        if trace:
            self.trace()

    def hugeverbose(self, *args, trace=False, **kwargs):
        """Logs a whole message in emboldened white text, and optionally the stack trace of the most recent exception.

        Args:
            *args: Variable-length argument list to pass to the logger.
            trace (bool, optional): Whether to log the stack trace of the most recently caught exception. Defaults to False.
            **kwargs: Arbitrary keyword arguments to pass to the logger.

        Examples:
            >>> self.hugeverbose("This is a huge verbose message")
            >>> self.hugeverbose("This is a huge verbose message with a trace", trace=True)
        """
        self.log.hugeverbose(*args, extra={"scan_id": self.scan.id}, **kwargs)
        if trace:
            self.trace()

    def info(self, *args, trace=False, **kwargs):
        """Logs informational messages and optionally the stack trace of the most recent exception.

        Args:
            *args: Variable-length argument list to pass to the logger.
            trace (bool, optional): Whether to log the stack trace of the most recently caught exception. Defaults to False.
            **kwargs: Arbitrary keyword arguments to pass to the logger.

        Examples:
            >>> self.info("This is an informational message")
            >>> self.info("This is an informational message with a trace", trace=True)
        """
        self.log.info(*args, extra={"scan_id": self.scan.id}, **kwargs)
        if trace:
            self.trace()

    def hugeinfo(self, *args, trace=False, **kwargs):
        """Logs a whole message in emboldened blue text, and optionally the stack trace of the most recent exception.

        Args:
            *args: Variable-length argument list to pass to the logger.
            trace (bool, optional): Whether to log the stack trace of the most recently caught exception. Defaults to False.
            **kwargs: Arbitrary keyword arguments to pass to the logger.

        Examples:
            >>> self.hugeinfo("This is a huge informational message")
            >>> self.hugeinfo("This is a huge informational message with a trace", trace=True)
        """
        self.log.hugeinfo(*args, extra={"scan_id": self.scan.id}, **kwargs)
        if trace:
            self.trace()

    def success(self, *args, trace=False, **kwargs):
        """Logs a success message, and optionally the stack trace of the most recent exception.

        Args:
            *args: Variable-length argument list to pass to the logger.
            trace (bool, optional): Whether to log the stack trace of the most recently caught exception. Defaults to False.
            **kwargs: Arbitrary keyword arguments to pass to the logger.

        Examples:
            >>> self.success("Operation completed successfully")
            >>> self.success("Operation completed with a trace", trace=True)
        """
        self.log.success(*args, extra={"scan_id": self.scan.id}, **kwargs)
        if trace:
            self.trace()

    def hugesuccess(self, *args, trace=False, **kwargs):
        """Logs a whole message in emboldened green text, and optionally the stack trace of the most recent exception.

        Args:
            *args: Variable-length argument list to pass to the logger.
            trace (bool, optional): Whether to log the stack trace of the most recently caught exception. Defaults to False.
            **kwargs: Arbitrary keyword arguments to pass to the logger.

        Examples:
            >>> self.hugesuccess("This is a huge success message")
            >>> self.hugesuccess("This is a huge success message with a trace", trace=True)
        """
        self.log.hugesuccess(*args, extra={"scan_id": self.scan.id}, **kwargs)
        if trace:
            self.trace()

    def warning(self, *args, trace=True, **kwargs):
        """Logs a warning message, and optionally the stack trace of the most recent exception.

        Args:
            *args: Variable-length argument list to pass to the logger.
            trace (bool, optional): Whether to log the stack trace of the most recently caught exception. Defaults to True.
            **kwargs: Arbitrary keyword arguments to pass to the logger.

        Examples:
            >>> self.warning("This is a warning message")
            >>> self.warning("This is a warning message with a trace", trace=False)
        """
        self.log.warning(*args, extra={"scan_id": self.scan.id}, **kwargs)
        if trace:
            self.trace()

    def hugewarning(self, *args, trace=True, **kwargs):
        """Logs a whole message in emboldened orange text, and optionally the stack trace of the most recent exception.

        Args:
            *args: Variable-length argument list to pass to the logger.
            trace (bool, optional): Whether to log the stack trace of the most recently caught exception. Defaults to True.
            **kwargs: Arbitrary keyword arguments to pass to the logger.

        Examples:
            >>> self.hugewarning("This is a huge warning message")
            >>> self.hugewarning("This is a huge warning message with a trace", trace=False)
        """
        self.log.hugewarning(*args, extra={"scan_id": self.scan.id}, **kwargs)
        if trace:
            self.trace()

    def error(self, *args, trace=True, **kwargs):
        """Logs an error message, and optionally the stack trace of the most recent exception.

        Args:
            *args: Variable-length argument list to pass to the logger.
            trace (bool, optional): Whether to log the stack trace of the most recently caught exception. Defaults to True.
            **kwargs: Arbitrary keyword arguments to pass to the logger.

        Examples:
            >>> self.error("This is an error message")
            >>> self.error("This is an error message with a trace", trace=False)
        """
        self.log.error(*args, extra={"scan_id": self.scan.id}, **kwargs)
        if trace:
            self.trace()

    def trace(self, msg=None):
        """Logs the stack trace of the most recently caught exception.

        This method captures the type, value, and traceback of the most recent exception and logs it using the trace level. It is typically used for debugging purposes.

        Anything logged using this method will always be written to the scan's `debug.log`, even if debugging is not enabled.

        Examples:
            >>> try:
            >>>     1 / 0
            >>> except ZeroDivisionError:
            >>>     self.trace()
        """
        if msg is None:
            e_type, e_val, e_traceback = exc_info()
            if e_type is not None:
                self.log.trace(traceback.format_exc())
        else:
            self.log.trace(msg)

    def critical(self, *args, trace=True, **kwargs):
        """Logs a whole message in emboldened red text, and optionally the stack trace of the most recent exception.

        Args:
            *args: Variable-length argument list to pass to the logger.
            trace (bool, optional): Whether to log the stack trace of the most recently caught exception. Defaults to True.
            **kwargs: Arbitrary keyword arguments to pass to the logger.

        Examples:
            >>> self.critical("This is a critical message")
            >>> self.critical("This is a critical message with a trace", trace=False)
        """
        self.log.critical(*args, extra={"scan_id": self.scan.id}, **kwargs)
        if trace:
            self.trace()


class InterceptModule(BaseModule):
    """
    An Intercept Module is a special type of high-priority module that gets early access to events.

    If you want your module to tag or modify an event before it's distributed to the scan, it should
    probably be an intercept module.

    Examples of intercept modules include `dns` (for DNS resolution and wildcard detection)
    and `cloud` (for detection and tagging of cloud assets).
    """

    accept_dupes = True
    suppress_dupes = False
    _intercept = True

    async def _worker(self):
        async with self.scan._acatch(context=self._worker, unhandled_is_critical=True):
            try:
                while not self.scan.stopping and not self.errored:
                    try:
                        if self.incoming_event_queue is not False:
                            incoming = await self.get_incoming_event()
                            try:
                                event, kwargs = incoming
                            except ValueError:
                                event = incoming
                                kwargs = {}
                        else:
                            self.debug(f"Event queue is in bad state")
                            break
                    except asyncio.queues.QueueEmpty:
                        await asyncio.sleep(0.1)
                        continue

                    if event.type == "FINISHED":
                        context = f"{self.name}.finish()"
                        async with self.scan._acatch(context), self._task_counter.count(context):
                            await self.finish()
                        continue

                    acceptable = True
                    async with self._task_counter.count(f"event_precheck({event})"):
                        precheck_pass, reason = self._event_precheck(event)
                    if not precheck_pass:
                        self.debug(f"Not intercepting {event} because precheck failed ({reason})")
                        acceptable = False
                    async with self._task_counter.count(f"event_postcheck({event})"):
                        postcheck_pass, reason = await self._event_postcheck(event)
                    if not postcheck_pass:
                        self.debug(f"Not intercepting {event} because postcheck failed ({reason})")
                        acceptable = False

                    # whether to pass the event on to the rest of the scan
                    # defaults to true, unless handle_event returns False
                    forward_event = True
                    forward_event_reason = ""

                    if acceptable:
                        context = f"{self.name}.handle_event({event, kwargs})"
                        self.scan.stats.event_consumed(event, self)
                        self.debug(f"Intercepting {event}")
                        async with self.scan._acatch(context), self._task_counter.count(context):
                            forward_event = await self.handle_event(event, **kwargs)
                            with suppress(ValueError, TypeError):
                                forward_event, forward_event_reason = forward_event

                        if forward_event is False:
                            self.debug(f"Not forwarding {event} because {forward_event_reason}")
                            continue

                    self.debug(f"Forwarding {event}")
                    await self.forward_event(event, kwargs)

            except asyncio.CancelledError:
                # this trace was used for debugging leaked CancelledErrors from inside httpx
                # self.log.trace("Worker cancelled")
                raise
            except BaseException as e:
                if self.helpers.in_exception_chain(e, (KeyboardInterrupt,)):
                    self.scan.stop()
                else:
                    self.critical(f"Critical failure in intercept module {self.name}: {e}")
                    self.critical(traceback.format_exc())
        self.log.trace(f"Worker stopped")

    async def get_incoming_event(self):
        """
        Get an event from this module's incoming event queue
        """
        return await self.incoming_event_queue.get()

    async def forward_event(self, event, kwargs):
        """
        Used for forwarding the event on to the next intercept module
        """
        await self.outgoing_event_queue.put((event, kwargs))

    async def queue_outgoing_event(self, event, **kwargs):
        """
        Used by emit_event() to raise new events to the scan
        """
        # if this was a normal module, we'd put it in the outgoing queue
        # but because it's an intercept module, we need to queue it at the scan's ingress
        await self.scan.ingress_module.queue_event(event, kwargs)

    async def queue_event(self, event, kwargs=None):
        """
        Put an event in this module's incoming event queue
        """
        if kwargs is None:
            kwargs = {}
        try:
            self.incoming_event_queue.put_nowait((event, kwargs))
        except AttributeError:
            self.debug(f"Not in an acceptable state to queue incoming event")

    async def _event_postcheck(self, event):
        return await self._event_postcheck_inner(event)
