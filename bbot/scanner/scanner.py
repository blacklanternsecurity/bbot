import sys
import asyncio
import logging
import traceback
import contextlib
import regex as re
from pathlib import Path
from sys import exc_info
from datetime import datetime
from collections import OrderedDict

from bbot import __version__

from bbot.core.event import make_event
from .manager import ScanIngress, ScanEgress
from bbot.core.helpers.misc import sha1, rand_string
from bbot.core.helpers.names_generator import random_name
from bbot.core.helpers.async_helpers import async_to_sync_gen
from bbot.errors import BBOTError, ScanError, ValidationError

log = logging.getLogger("bbot.scanner")


class Scanner:
    """A class representing a single BBOT scan

    Examples:
        Create scan with multiple targets:
        >>> my_scan = Scanner("evilcorp.com", "1.2.3.0/24", modules=["portscan", "sslcert", "httpx"])

        Create scan with custom config:
        >>> config = {"http_proxy": "http://127.0.0.1:8080", "modules": {"portscan": {"top_ports": 2000}}}
        >>> my_scan = Scanner("www.evilcorp.com", modules=["portscan", "httpx"], config=config)

        Start the scan, iterating over events as they're discovered (synchronous):
        >>> for event in my_scan.start():
        >>>     print(event)

        Start the scan, iterating over events as they're discovered (asynchronous):
        >>> async for event in my_scan.async_start():
        >>>     print(event)

        Start the scan without consuming events (synchronous):
        >>> my_scan.start_without_generator()

        Start the scan without consuming events (asynchronous):
        >>> await my_scan.async_start_without_generator()

    Attributes:
        status (str): Status of scan, representing its current state. It can take on the following string values, each of which is mapped to an integer code in `_status_codes`:
            ```markdown
            - "NOT_STARTED" (0): Initial status before the scan starts.
            - "STARTING" (1): Status when the scan is initializing.
            - "RUNNING" (2): Status when the scan is in progress.
            - "FINISHING" (3): Status when the scan is in the process of finalizing.
            - "CLEANING_UP" (4): Status when the scan is cleaning up resources.
            - "ABORTING" (5): Status when the scan is in the process of being aborted.
            - "ABORTED" (6): Status when the scan has been aborted.
            - "FAILED" (7): Status when the scan has encountered a failure.
            - "FINISHED" (8): Status when the scan has successfully completed.
            ```
        _status_code (int): The numerical representation of the current scan status, stored for internal use. It is mapped according to the values in `_status_codes`.
        target (Target): Target of scan (alias to `self.preset.target`).
        preset (Preset): The main scan Preset in its baked form.
        config (omegaconf.dictconfig.DictConfig): BBOT config (alias to `self.preset.config`).
        whitelist (Target): Scan whitelist (by default this is the same as `target`) (alias to `self.preset.whitelist`).
        blacklist (Target): Scan blacklist (this takes ultimate precedence) (alias to `self.preset.blacklist`).
        helpers (ConfigAwareHelper): Helper containing various reusable functions, regexes, etc. (alias to `self.preset.helpers`).
        output_dir (pathlib.Path): Output directory for scan (alias to `self.preset.output_dir`).
        name (str): Name of scan (alias to `self.preset.scan_name`).
        dispatcher (Dispatcher): Triggers certain events when the scan `status` changes.
        modules (dict): Holds all loaded modules in this format: `{"module_name": Module()}`.
        stats (ScanStats): Holds high-level scan statistics such as how many events have been produced and consumed by each module.
        home (pathlib.Path): Base output directory of the scan (default: `~/.bbot/scans/<scan_name>`).
        running (bool): Whether the scan is currently running.
        stopping (bool): Whether the scan is currently stopping.
        stopped (bool): Whether the scan is currently stopped.
        aborting (bool): Whether the scan is aborted or currently aborting.

    Notes:
        - The status is read-only once set to "ABORTING" until it transitions to "ABORTED."
        - Invalid statuses are logged but not applied.
        - Setting a status will trigger the `on_status` event in the dispatcher.
    """

    _status_codes = {
        "NOT_STARTED": 0,
        "STARTING": 1,
        "RUNNING": 2,
        "FINISHING": 3,
        "CLEANING_UP": 4,
        "ABORTING": 5,
        "ABORTED": 6,
        "FAILED": 7,
        "FINISHED": 8,
    }

    def __init__(
        self,
        *targets,
        scan_id=None,
        dispatcher=None,
        **kwargs,
    ):
        """
        Initializes the Scanner class.

        If a premade `preset` is specified, it will be used for the scan.
        Otherwise, `Scan` accepts the same arguments as `Preset`, which are passed through and used to create a new preset.

        Args:
            *targets (list[str], optional): Scan targets (passed through to `Preset`).
            preset (Preset, optional): Preset to use for the scan.
            scan_id (str, optional): Unique identifier for the scan. Auto-generates if None.
            dispatcher (Dispatcher, optional): Dispatcher object to use. Defaults to new Dispatcher.
            **kwargs (list[str], optional): Additional keyword arguments (passed through to `Preset`).
        """
        self._root_event = None
        self._finish_event = None
        self.start_time = None
        self.end_time = None
        self.duration = None
        self.duration_human = None
        self.duration_seconds = None

        self._success = False

        if scan_id is not None:
            self.id = str(id)
        else:
            self.id = f"SCAN:{sha1(rand_string(20)).hexdigest()}"

        custom_preset = kwargs.pop("preset", None)
        kwargs["_log"] = True

        from .preset import Preset

        base_preset = Preset(*targets, **kwargs)

        if custom_preset is not None:
            if not isinstance(custom_preset, Preset):
                raise ValidationError(f'Preset must be of type Preset, not "{type(custom_preset).__name__}"')
            base_preset.merge(custom_preset)

        self.preset = base_preset.bake(self)

        # scan name
        if self.preset.scan_name is None:
            tries = 0
            while 1:
                if tries > 5:
                    scan_name = f"{rand_string(4)}_{rand_string(4)}"
                    break
                scan_name = random_name()
                if self.preset.output_dir is not None:
                    home_path = Path(self.preset.output_dir).resolve() / scan_name
                else:
                    home_path = self.preset.bbot_home / "scans" / scan_name
                if not home_path.exists():
                    break
                tries += 1
        else:
            scan_name = str(self.preset.scan_name)
        self.name = scan_name

        # make sure the preset has a description
        if not self.preset.description:
            self.preset.description = self.name

        # scan output dir
        if self.preset.output_dir is not None:
            self.home = Path(self.preset.output_dir).resolve() / self.name
        else:
            self.home = self.preset.bbot_home / "scans" / self.name

        self._status = "NOT_STARTED"
        self._status_code = 0

        self.modules = OrderedDict({})
        self._modules_loaded = False
        self.dummy_modules = {}

        if dispatcher is None:
            from .dispatcher import Dispatcher

            self.dispatcher = Dispatcher()
        else:
            self.dispatcher = dispatcher
        self.dispatcher.set_scan(self)

        # scope distance
        self.scope_config = self.config.get("scope", {})
        self.scope_search_distance = max(0, int(self.scope_config.get("search_distance", 0)))
        self.scope_report_distance = int(self.scope_config.get("report_distance", 1))

        # web config
        self.web_config = self.config.get("web", {})
        self.web_spider_distance = self.web_config.get("spider_distance", 0)
        self.web_spider_depth = self.web_config.get("spider_depth", 1)
        self.web_spider_links_per_page = self.web_config.get("spider_links_per_page", 20)
        max_redirects = self.web_config.get("http_max_redirects", 5)
        self.web_max_redirects = max(max_redirects, self.web_spider_distance)
        self.http_proxy = self.web_config.get("http_proxy", "")
        self.http_timeout = self.web_config.get("http_timeout", 10)
        self.httpx_timeout = self.web_config.get("httpx_timeout", 5)
        self.http_retries = self.web_config.get("http_retries", 1)
        self.httpx_retries = self.web_config.get("httpx_retries", 1)
        self.useragent = self.web_config.get("user_agent", "BBOT")
        # custom HTTP headers warning
        self.custom_http_headers = self.web_config.get("http_headers", {})
        if self.custom_http_headers:
            self.warning(
                "You have enabled custom HTTP headers. These will be attached to all in-scope requests and all requests made by httpx."
            )

        # url file extensions
        self.url_extension_blacklist = set(e.lower() for e in self.config.get("url_extension_blacklist", []))
        self.url_extension_httpx_only = set(e.lower() for e in self.config.get("url_extension_httpx_only", []))

        # url querystring behavior
        self.url_querystring_remove = self.config.get("url_querystring_remove", True)

        # blob inclusion
        self._file_blobs = self.config.get("file_blobs", False)
        self._folder_blobs = self.config.get("folder_blobs", False)

        # how often to print scan status
        self.status_frequency = self.config.get("status_frequency", 15)

        from .stats import ScanStats

        self.stats = ScanStats(self)

        self._prepped = False
        self._finished_init = False
        self._new_activity = False
        self._cleanedup = False
        self._omitted_event_types = None

        self.__loop = None
        self._manager_worker_loop_tasks = []
        self.init_events_task = None
        self.ticker_task = None
        self.dispatcher_tasks = []

        self._stopping = False

        self._dns_strings = None
        self._dns_regexes = None
        self._dns_regexes_yara = None
        self._dns_yara_rules_uncompiled = None
        self._dns_yara_rules = None

        self.__log_handlers = None
        self._log_handler_backup = []

    async def _prep(self):
        """
        Creates the scan's output folder, loads its modules, and calls their .setup() methods.
        """

        self.helpers.mkdir(self.home)
        if not self._prepped:
            # save scan preset
            with open(self.home / "preset.yml", "w") as f:
                f.write(self.preset.to_yaml())

            # log scan overview
            start_msg = f"Scan with {len(self.preset.scan_modules):,} modules seeded with {len(self.target):,} targets"
            details = []
            if self.whitelist != self.target:
                details.append(f"{len(self.whitelist):,} in whitelist")
            if self.blacklist:
                details.append(f"{len(self.blacklist):,} in blacklist")
            if details:
                start_msg += f" ({', '.join(details)})"
            self.hugeinfo(start_msg)

            # load scan modules (this imports and instantiates them)
            # up to this point they were only preloaded
            await self.load_modules()

            # run each module's .setup() method
            succeeded, hard_failed, soft_failed = await self.setup_modules()

            # intercept modules get sewn together like human centipede
            self.intercept_modules = [m for m in self.modules.values() if m._intercept]
            for i, intercept_module in enumerate(self.intercept_modules[1:]):
                prev_intercept_module = self.intercept_modules[i]
                self.debug(
                    f"Setting intercept module {intercept_module.name}._incoming_event_queue to previous intercept module {prev_intercept_module.name}.outgoing_event_queue"
                )
                interqueue = asyncio.Queue()
                intercept_module._incoming_event_queue = interqueue
                prev_intercept_module._outgoing_event_queue = interqueue

            # abort if there are no output modules
            num_output_modules = len([m for m in self.modules.values() if m._type == "output"])
            if num_output_modules < 1:
                raise ScanError("Failed to load output modules. Aborting.")
            # abort if any of the module .setup()s hard-failed (i.e. they errored or returned False)
            total_failed = len(hard_failed + soft_failed)
            if hard_failed:
                msg = f"Setup hard-failed for {len(hard_failed):,} modules ({','.join(hard_failed)})"
                self._fail_setup(msg)

            total_modules = total_failed + len(self.modules)
            success_msg = f"Setup succeeded for {len(self.modules):,}/{total_modules:,} modules."

            self.success(success_msg)
            self._prepped = True

    def start(self):
        for event in async_to_sync_gen(self.async_start()):
            yield event

    def start_without_generator(self):
        for event in async_to_sync_gen(self.async_start()):
            pass

    async def async_start_without_generator(self):
        async for event in self.async_start():
            pass

    async def async_start(self):
        """ """
        self.start_time = datetime.now()
        self.root_event.data["started_at"] = self.start_time.isoformat()
        try:
            await self._prep()

            self._start_log_handlers()
            self.trace(f'Ran BBOT {__version__} at {self.start_time}, command: {" ".join(sys.argv)}')
            self.trace(f"Target: {self.preset.target.json}")
            self.trace(f"Preset: {self.preset.to_dict(redact_secrets=True)}")

            if not self.target:
                self.warning(f"No scan targets specified")

            # start status ticker
            self.ticker_task = asyncio.create_task(
                self._status_ticker(self.status_frequency), name=f"{self.name}._status_ticker()"
            )

            self.status = "STARTING"

            if not self.modules:
                self.error(f"No modules loaded")
                self.status = "FAILED"
                return
            else:
                self.hugesuccess(f"Starting scan {self.name}")

            await self.dispatcher.on_start(self)

            self.status = "RUNNING"
            self._start_modules()
            self.verbose(f"{len(self.modules):,} modules started")

            # distribute seed events
            self.init_events_task = asyncio.create_task(
                self.ingress_module.init_events(self.target.events), name=f"{self.name}.ingress_module.init_events()"
            )

            # main scan loop
            while 1:
                # abort if we're aborting
                if self.aborting:
                    self._drain_queues()
                    break

                # yield events as they come (async for event in scan.async_start())
                if "python" in self.modules:
                    events, finish = await self.modules["python"]._events_waiting(batch_size=-1)
                    for e in events:
                        yield e
                    if events:
                        continue

                # break if initialization finished and the scan is no longer active
                if self._finished_init and self.modules_finished:
                    new_activity = await self.finish()
                    if not new_activity:
                        self._success = True
                        scan_finish_event = await self._mark_finished()
                        yield scan_finish_event
                        break

                await asyncio.sleep(0.1)

            self._success = True

        except BaseException as e:
            if self.helpers.in_exception_chain(e, (KeyboardInterrupt, asyncio.CancelledError)):
                self.stop()
                self._success = True
            else:
                try:
                    raise
                except ScanError as e:
                    self.error(f"{e}")

                except BBOTError as e:
                    self.critical(f"Error during scan: {e}")

                except Exception:
                    self.critical(f"Unexpected error during scan:\n{traceback.format_exc()}")

        finally:
            tasks = self._cancel_tasks()
            self.debug(f"Awaiting {len(tasks):,} tasks")
            for task in tasks:
                # self.debug(f"Awaiting {task}")
                with contextlib.suppress(BaseException):
                    await asyncio.wait_for(task, timeout=0.1)
            self.debug(f"Awaited {len(tasks):,} tasks")
            await self._report()
            await self._cleanup()

            await self.dispatcher.on_finish(self)

            self._stop_log_handlers()

    async def _mark_finished(self):
        log_fn = self.hugesuccess
        if self.status == "ABORTING":
            status = "ABORTED"
            log_fn = self.hugewarning
        elif not self._success:
            status = "FAILED"
            log_fn = self.critical
        else:
            status = "FINISHED"

        self.end_time = datetime.now()
        self.duration = self.end_time - self.start_time
        self.duration_seconds = self.duration.total_seconds()
        self.duration_human = self.helpers.human_timedelta(self.duration)

        status_message = f"Scan {self.name} completed in {self.duration_human} with status {status}"

        scan_finish_event = self.finish_event(status_message, status)

        # queue final scan event with output modules
        output_modules = [m for m in self.modules.values() if m._type == "output" and m.name != "python"]
        for m in output_modules:
            await m.queue_event(scan_finish_event)
        # wait until output modules are flushed
        while 1:
            modules_finished = all([m.finished for m in output_modules])
            if modules_finished:
                break
            await asyncio.sleep(0.05)

        self.status = status
        log_fn(status_message)
        return scan_finish_event

    def _start_modules(self):
        self.verbose(f"Starting module worker loops")
        for module in self.modules.values():
            module.start()

    async def setup_modules(self, remove_failed=True):
        """Asynchronously initializes all loaded modules by invoking their `setup()` methods.

        Args:
            remove_failed (bool): Flag indicating whether to remove modules that fail setup.

        Returns:
            tuple:
                succeeded - List of modules that successfully set up.
                hard_failed - List of modules that encountered a hard failure during setup.
                soft_failed - List of modules that encountered a soft failure during setup.

        Raises:
            ScanError: If no output modules could be loaded.

        Notes:
            Hard-failed modules are set to an error state and removed if `remove_failed` is True.
            Soft-failed modules are not set to an error state but are also removed if `remove_failed` is True.
        """
        await self.load_modules()
        self.verbose(f"Setting up modules")
        succeeded = []
        hard_failed = []
        soft_failed = []

        async for task in self.helpers.as_completed([m._setup() for m in self.modules.values()]):
            module, status, msg = await task
            if status == True:
                self.debug(f"Setup succeeded for {module.name} ({msg})")
                succeeded.append(module.name)
            elif status == False:
                self.warning(f"Setup hard-failed for {module.name}: {msg}")
                self.modules[module.name].set_error_state()
                hard_failed.append(module.name)
            else:
                self.info(f"Setup soft-failed for {module.name}: {msg}")
                soft_failed.append(module.name)
            if (not status) and (module._intercept or remove_failed):
                # if a intercept module fails setup, we always remove it
                self.modules.pop(module.name)

        return succeeded, hard_failed, soft_failed

    async def load_modules(self):
        """Asynchronously import and instantiate all scan modules, including internal and output modules.

        This method is automatically invoked by `setup_modules()`. It performs several key tasks in the following sequence:

        1. Install dependencies for each module via `self.helpers.depsinstaller.install()`.
        2. Load scan modules and updates the `modules` dictionary.
        3. Load internal modules and updates the `modules` dictionary.
        4. Load output modules and updates the `modules` dictionary.
        5. Sorts modules based on their `_priority` attribute.

        If any modules fail to load or their dependencies fail to install, a ScanError will be raised (unless `self.force_start` is True).

        Attributes:
            succeeded, failed (tuple): A tuple containing lists of modules that succeeded or failed during the dependency installation.
            loaded_modules, loaded_internal_modules, loaded_output_modules (dict): Dictionaries of successfully loaded modules.
            failed, failed_internal, failed_output (list): Lists of module names that failed to load.

        Raises:
            ScanError: If any module dependencies fail to install or modules fail to load, and if `self.force_start` is False.

        Returns:
            None

        Note:
            After all modules are loaded, they are sorted by `_priority` and stored in the `modules` dictionary.
        """
        if not self._modules_loaded:
            if not self.preset.modules:
                self.warning(f"No modules to load")
                return

            if not self.preset.scan_modules:
                self.warning(f"No scan modules to load")

            # install module dependencies
            succeeded, failed = await self.helpers.depsinstaller.install(*self.preset.modules)
            if failed:
                msg = f"Failed to install dependencies for {len(failed):,} modules: {','.join(failed)}"
                self._fail_setup(msg)
            modules = sorted([m for m in self.preset.scan_modules if m in succeeded])
            output_modules = sorted([m for m in self.preset.output_modules if m in succeeded])
            internal_modules = sorted([m for m in self.preset.internal_modules if m in succeeded])

            # Load scan modules
            self.verbose(f"Loading {len(modules):,} scan modules: {','.join(modules)}")
            loaded_modules, failed = self._load_modules(modules)
            self.modules.update(loaded_modules)
            if len(failed) > 0:
                msg = f"Failed to load {len(failed):,} scan modules: {','.join(failed)}"
                self._fail_setup(msg)
            if loaded_modules:
                self.info(
                    f"Loaded {len(loaded_modules):,}/{len(self.preset.scan_modules):,} scan modules ({','.join(loaded_modules)})"
                )

            # Load internal modules
            self.verbose(f"Loading {len(internal_modules):,} internal modules: {','.join(internal_modules)}")
            loaded_internal_modules, failed_internal = self._load_modules(internal_modules)
            self.modules.update(loaded_internal_modules)
            if len(failed_internal) > 0:
                msg = f"Failed to load {len(loaded_internal_modules):,} internal modules: {','.join(loaded_internal_modules)}"
                self._fail_setup(msg)
            if loaded_internal_modules:
                self.info(
                    f"Loaded {len(loaded_internal_modules):,}/{len(self.preset.internal_modules):,} internal modules ({','.join(loaded_internal_modules)})"
                )

            # Load output modules
            self.verbose(f"Loading {len(output_modules):,} output modules: {','.join(output_modules)}")
            loaded_output_modules, failed_output = self._load_modules(output_modules)
            self.modules.update(loaded_output_modules)
            if len(failed_output) > 0:
                msg = f"Failed to load {len(failed_output):,} output modules: {','.join(failed_output)}"
                self._fail_setup(msg)
            if loaded_output_modules:
                self.info(
                    f"Loaded {len(loaded_output_modules):,}/{len(self.preset.output_modules):,} output modules, ({','.join(loaded_output_modules)})"
                )

            # builtin intercept modules
            self.ingress_module = ScanIngress(self)
            self.egress_module = ScanEgress(self)
            self.modules[self.ingress_module.name] = self.ingress_module
            self.modules[self.egress_module.name] = self.egress_module

            # sort modules by priority
            self.modules = OrderedDict(sorted(self.modules.items(), key=lambda x: getattr(x[-1], "priority", 3)))

            self._modules_loaded = True

    @property
    def modules_finished(self):
        finished_modules = [m.finished for m in self.modules.values()]
        return all(finished_modules)

    def kill_module(self, module_name, message=None):
        from signal import SIGINT

        module = self.modules[module_name]
        if module._intercept:
            self.warning(f'Cannot kill module "{module_name}" because it is critical to the scan')
            return
        module.set_error_state(message=message, clear_outgoing_queue=True)
        for proc in module._proc_tracker:
            with contextlib.suppress(Exception):
                proc.send_signal(SIGINT)
        self.helpers.cancel_tasks_sync(module._tasks)

    @property
    def incoming_event_queues(self):
        return self.ingress_module.incoming_queues

    @property
    def num_queued_events(self):
        total = 0
        for q in self.incoming_event_queues:
            total += len(q._queue)
        return total

    def modules_status(self, _log=False):
        finished = True
        status = {"modules": {}}

        sorted_modules = []
        for module_name, module in self.modules.items():
            if module_name.startswith("_"):
                continue
            sorted_modules.append(module)
            mod_status = module.status
            if mod_status["running"]:
                finished = False
            status["modules"][module_name] = mod_status

        # sort modules by name
        sorted_modules.sort(key=lambda m: m.name)

        status["finished"] = finished

        modules_errored = [m for m, s in status["modules"].items() if s["errored"]]

        max_mem_percent = 90
        mem_status = self.helpers.memory_status()
        # abort if we don't have the memory
        mem_percent = mem_status.percent
        if mem_percent > max_mem_percent:
            free_memory = mem_status.available
            free_memory_human = self.helpers.bytes_to_human(free_memory)
            self.warning(f"System memory is at {mem_percent:.1f}% ({free_memory_human} remaining)")

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
                self.info(f"{self.name}: Modules running (incoming:processing:outgoing) {modules_status_str}")
            else:
                self.info(f"{self.name}: No modules running")
            event_type_summary = sorted(self.stats.events_emitted_by_type.items(), key=lambda x: x[-1], reverse=True)
            if event_type_summary:
                self.info(
                    f'{self.name}: Events produced so far: {", ".join([f"{k}: {v}" for k,v in event_type_summary])}'
                )
            else:
                self.info(f"{self.name}: No events produced yet")

            if modules_errored:
                self.verbose(
                    f'{self.name}: Modules errored: {len(modules_errored):,} ({", ".join([m for m in modules_errored])})'
                )

            num_queued_events = self.num_queued_events
            if num_queued_events:
                self.info(
                    f"{self.name}: {num_queued_events:,} events in queue ({self.stats.speedometer.speed:,} processed in the past {self.status_frequency} seconds)"
                )
            else:
                self.info(
                    f"{self.name}: No events in queue ({self.stats.speedometer.speed:,} processed in the past {self.status_frequency} seconds)"
                )

            if self.log_level <= logging.DEBUG:
                # status debugging
                scan_active_status = []
                scan_active_status.append(f"scan._finished_init: {self._finished_init}")
                scan_active_status.append(f"scan.modules_finished: {self.modules_finished}")
                for m in sorted_modules:
                    running = m.running
                    scan_active_status.append(f"    {m}:")
                    # scan_active_status.append(f"        running: {running}")
                    if running:
                        # scan_active_status.append(f"        tasks:")
                        for task in list(m._task_counter.tasks.values()):
                            scan_active_status.append(f"        - {task}:")
                    # scan_active_status.append(f"        incoming_queue_size: {m.num_incoming_events}")
                    # scan_active_status.append(f"        outgoing_queue_size: {m.outgoing_event_queue.qsize()}")
                for line in scan_active_status:
                    self.debug(line)

                # log module memory usage
                module_memory_usage = []
                for module in sorted_modules:
                    memory_usage = module.memory_usage
                    module_memory_usage.append((module.name, memory_usage))
                module_memory_usage.sort(key=lambda x: x[-1], reverse=True)
                self.debug(f"MODULE MEMORY USAGE:")
                for module_name, usage in module_memory_usage:
                    self.debug(f"    - {module_name}: {self.helpers.bytes_to_human(usage)}")

        status.update({"modules_errored": len(modules_errored)})

        return status

    def stop(self):
        """Stops the in-progress scan and performs necessary cleanup.

        This method sets the scan's status to "ABORTING," cancels any pending tasks, and drains event queues. It also kills child processes spawned during the scan.

        Returns:
            None
        """
        if not self._stopping:
            self._stopping = True
            self.status = "ABORTING"
            self.hugewarning("Aborting scan")
            self.trace()
            self._cancel_tasks()
            self._drain_queues()
            self.helpers.kill_children()
            self._drain_queues()
            self.helpers.kill_children()
            self.debug("Finished aborting scan")

    async def finish(self):
        """Finalizes the scan by invoking the `finished()` method on all active modules if new activity is detected.

        The method is idempotent and will return False if no new activity has been recorded since the last invocation.

        Returns:
            bool: True if new activity has been detected and the `finished()` method is invoked on all modules.
                  False if no new activity has been detected since the last invocation.

        Notes:
            This method alters the scan's status to "FINISHING" if new activity is detected.
        """
        # if new events were generated since last time we were here
        if self._new_activity:
            self._new_activity = False
            self.status = "FINISHING"
            # Trigger .finished() on every module and start over
            log.info("Finishing scan")
            for module in self.modules.values():
                finished_event = self.make_event(f"FINISHED", "FINISHED", dummy=True, tags={module.name})
                await module.queue_event(finished_event)
            self.verbose("Completed finish()")
            return True
        self.verbose("Completed final finish()")
        # Return False if no new events were generated since last time
        return False

    def _drain_queues(self):
        """Empties all the event queues for each loaded module and the manager's incoming event queue.

        This method iteratively empties both the incoming and outgoing event queues of each module, as well as the incoming event queue of the scan manager.

        Returns:
            None
        """
        self.debug("Draining queues")
        for module in self.modules.values():
            with contextlib.suppress(asyncio.queues.QueueEmpty):
                while 1:
                    if module.incoming_event_queue not in (None, False):
                        module.incoming_event_queue.get_nowait()
            with contextlib.suppress(asyncio.queues.QueueEmpty):
                while 1:
                    if module.outgoing_event_queue not in (None, False):
                        module.outgoing_event_queue.get_nowait()
        self.debug("Finished draining queues")

    def _cancel_tasks(self):
        """Cancels all asynchronous tasks and shuts down the process pool.

        This method collects all pending tasks from each module, the dispatcher,
        and the scan manager. After collecting these tasks, it cancels them synchronously
        using a helper function. Finally, it shuts down the process pool, canceling any
        pending futures.

        Returns:
            None
        """
        self.debug("Cancelling all scan tasks")
        tasks = []
        # module workers
        for m in self.modules.values():
            tasks += getattr(m, "_tasks", [])
        # init events
        if self.init_events_task:
            tasks.append(self.init_events_task)
        # ticker
        if self.ticker_task:
            tasks.append(self.ticker_task)
        # dispatcher
        tasks += self.dispatcher_tasks
        # manager worker loops
        tasks += self._manager_worker_loop_tasks
        self.helpers.cancel_tasks_sync(tasks)
        # process pool
        self.helpers.process_pool.shutdown(cancel_futures=True)
        self.debug("Finished cancelling all scan tasks")
        return tasks

    async def _report(self):
        """Asynchronously executes the `report()` method for each module in the scan.

        This method is called once at the end of each scan and is responsible for
        triggering the `report()` function for each module. It executes irrespective
        of whether the scan was aborted or completed successfully. The method makes
        use of an asynchronous context manager (`_acatch`) to handle exceptions and
        a task counter to keep track of the task's context.

        Returns:
            None
        """
        for mod in self.modules.values():
            context = f"{mod.name}.report()"
            async with self._acatch(context), mod._task_counter.count(context):
                await mod.report()

    async def _cleanup(self):
        """Asynchronously executes the `cleanup()` method for each module in the scan.

        This method is called once at the end of the scan to perform resource cleanup
        tasks. It is executed regardless of whether the scan was aborted or completed
        successfully. The scan status is set to "CLEANING_UP" during the execution.
        After calling the `cleanup()` method for each module, it performs additional
        cleanup tasks such as removing the scan's home directory if empty and cleaning
        old scans.

        Returns:
            None
        """
        # clean up self
        if not self._cleanedup:
            self._cleanedup = True
            self.status = "CLEANING_UP"
            # clean up dns engine
            if self.helpers._dns is not None:
                await self.helpers.dns.shutdown()
            # clean up web engine
            if self.helpers._web is not None:
                await self.helpers.web.shutdown()
            # clean up modules
            for mod in self.modules.values():
                await mod._cleanup()
            with contextlib.suppress(Exception):
                self.home.rmdir()
            self.helpers.clean_old_scans()

    def in_scope(self, *args, **kwargs):
        return self.preset.in_scope(*args, **kwargs)

    def whitelisted(self, *args, **kwargs):
        return self.preset.whitelisted(*args, **kwargs)

    def blacklisted(self, *args, **kwargs):
        return self.preset.blacklisted(*args, **kwargs)

    @property
    def core(self):
        return self.preset.core

    @property
    def config(self):
        return self.preset.core.config

    @property
    def target(self):
        return self.preset.target

    @property
    def whitelist(self):
        return self.preset.whitelist

    @property
    def blacklist(self):
        return self.preset.blacklist

    @property
    def helpers(self):
        return self.preset.helpers

    @property
    def force_start(self):
        return self.preset.force_start

    @property
    def word_cloud(self):
        return self.helpers.word_cloud

    @property
    def stopping(self):
        return not self.running

    @property
    def stopped(self):
        return self._status_code > 5

    @property
    def running(self):
        return 0 < self._status_code < 4

    @property
    def aborting(self):
        return 5 <= self._status_code <= 6

    @property
    def status(self):
        return self._status

    @property
    def omitted_event_types(self):
        if self._omitted_event_types is None:
            self._omitted_event_types = self.config.get("omit_event_types", [])
        return self._omitted_event_types

    @status.setter
    def status(self, status):
        """
        Block setting after status has been aborted
        """
        status = str(status).strip().upper()
        if status in self._status_codes:
            if self.status == "ABORTING" and not status == "ABORTED":
                self.debug(f'Attempt to set invalid status "{status}" on aborted scan')
            else:
                if status != self._status:
                    self._status = status
                    self._status_code = self._status_codes[status]
                    self.dispatcher_tasks.append(
                        asyncio.create_task(
                            self.dispatcher.catch(self.dispatcher.on_status, self._status, self.id),
                            name=f"{self.name}.dispatcher.on_status({status})",
                        )
                    )
                else:
                    self.debug(f'Scan status is already "{status}"')
        else:
            self.debug(f'Attempt to set invalid status "{status}" on scan')

    def make_event(self, *args, **kwargs):
        kwargs["scan"] = self
        event = make_event(*args, **kwargs)
        return event

    @property
    def root_event(self):
        """
        The root scan event, e.g.:
            ```json
            {
              "type": "SCAN",
              "id": "SCAN:1188928d942ace8e3befae0bdb9c3caa22705f54",
              "data": "pixilated_kathryn (SCAN:1188928d942ace8e3befae0bdb9c3caa22705f54)",
              "scope_distance": 0,
              "scan": "SCAN:1188928d942ace8e3befae0bdb9c3caa22705f54",
              "timestamp": 1694548779.616255,
              "parent": "SCAN:1188928d942ace8e3befae0bdb9c3caa22705f54",
              "tags": [
                "distance-0"
              ],
              "module": "TARGET",
              "module_sequence": "TARGET"
            }
            ```
        """
        if self._root_event is None:
            self._root_event = self.make_root_event(f"Scan {self.name} started at {self.start_time}")
        self._root_event.data["status"] = self.status
        return self._root_event

    def finish_event(self, context=None, status=None):
        if self._finish_event is None:
            if context is None or status is None:
                raise ValueError("Must specify context and status")
            self._finish_event = self.make_root_event(context)
            self._finish_event.data["status"] = status
        return self._finish_event

    def make_root_event(self, context):
        root_event = self.make_event(data=self.json, event_type="SCAN", dummy=True, context=context)
        root_event._id = self.id
        root_event.scope_distance = 0
        root_event.parent = root_event
        root_event.module = self._make_dummy_module(name="TARGET", _type="TARGET")
        return root_event

    @property
    def dns_strings(self):
        """
        A list of DNS hostname strings generated from the scan target
        """
        if self._dns_strings is None:
            dns_whitelist = set(t.host for t in self.whitelist if t.host and isinstance(t.host, str))
            dns_whitelist = sorted(dns_whitelist, key=len)
            dns_whitelist_set = set()
            dns_strings = []
            for t in dns_whitelist:
                if not any(x in dns_whitelist_set for x in self.helpers.domain_parents(t, include_self=True)):
                    dns_whitelist_set.add(t)
                    dns_strings.append(t)
            self._dns_strings = dns_strings
        return self._dns_strings

    def _generate_dns_regexes(self, pattern):
        """
        Generates a list of compiled DNS hostname regexes based on the provided pattern.
        This method centralizes the regex compilation to avoid redundancy in the dns_regexes and dns_regexes_yara methods.

        Args:
            pattern (str):
        Returns:
            list[re.Pattern]: A list of compiled regex patterns if enabled, otherwise an empty list.
        """

        dns_regexes = []
        for t in self.dns_strings:
            regex_pattern = re.compile(f"{pattern}{re.escape(t)})", re.I)
            log.debug(f"Generated Regex [{regex_pattern.pattern}] for domain {t}")
            dns_regexes.append(regex_pattern)
        return dns_regexes

    @property
    def dns_regexes(self):
        """
        A list of DNS hostname regexes generated from the scan target
        For the purpose of extracting hostnames

        Examples:
            Extract hostnames from text:
            >>> for regex in scan.dns_regexes:
            ...     for match in regex.finditer(response.text):
            ...         hostname = match.group().lower()
        """
        if self._dns_regexes is None:
            self._dns_regexes = self._generate_dns_regexes(r"((?:(?:[\w-]+)\.)+")
        return self._dns_regexes

    @property
    def dns_regexes_yara(self):
        """
        Returns a list of DNS hostname regexes formatted specifically for compatibility with YARA rules.
        """
        if self._dns_regexes_yara is None:
            self._dns_regexes_yara = self._generate_dns_regexes(r"(([a-z0-9-]+\.)*")
        return self._dns_regexes_yara

    @property
    def dns_yara_rules_uncompiled(self):
        if self._dns_yara_rules_uncompiled is None:
            regexes_component_list = []
            for i, r in enumerate(self.dns_regexes_yara):
                regexes_component_list.append(rf"$dns_name_{i} = /\b{r.pattern}/ nocase")
            if regexes_component_list:
                regexes_component = " ".join(regexes_component_list)
                self._dns_yara_rules_uncompiled = f'rule hostname_extraction {{meta: description = "matches DNS hostname pattern derived from target(s)" strings: {regexes_component} condition: any of them}}'
        return self._dns_yara_rules_uncompiled

    async def dns_yara_rules(self):
        if self._dns_yara_rules is None:
            if self.dns_yara_rules_uncompiled is not None:
                import yara

                self._dns_yara_rules = await self.helpers.run_in_executor(
                    yara.compile, source=self.dns_yara_rules_uncompiled
                )
        return self._dns_yara_rules

    async def extract_in_scope_hostnames(self, s):
        """
        Given a string, uses yara to extract hostnames matching scan targets

        Examples:
            >>> await self.scan.extract_in_scope_hostnames("http://www.evilcorp.com")
            ... {"www.evilcorp.com"}
        """
        matches = set()
        dns_yara_rules = await self.dns_yara_rules()
        if dns_yara_rules is not None:
            for match in await self.helpers.run_in_executor(dns_yara_rules.match, data=s):
                for string in match.strings:
                    for instance in string.instances:
                        matches.add(str(instance))
        return matches

    @property
    def json(self):
        """
        A dictionary representation of the scan including its name, ID, targets, whitelist, blacklist, and modules
        """
        j = dict()
        for i in ("id", "name"):
            v = getattr(self, i, "")
            if v:
                j.update({i: v})
        j["target"] = self.preset.target.json
        j["preset"] = self.preset.to_dict(redact_secrets=True)
        if self.start_time is not None:
            j["started_at"] = self.start_time.isoformat()
        if self.end_time is not None:
            j["finished_at"] = self.end_time.isoformat()
        if self.duration is not None:
            j["duration_seconds"] = self.duration_seconds
        if self.duration_human is not None:
            j["duration"] = self.duration_human
        return j

    def debug(self, *args, trace=False, **kwargs):
        log.debug(*args, extra={"scan_id": self.id}, **kwargs)
        if trace:
            self.trace()

    def verbose(self, *args, trace=False, **kwargs):
        log.verbose(*args, extra={"scan_id": self.id}, **kwargs)
        if trace:
            self.trace()

    def hugeverbose(self, *args, trace=False, **kwargs):
        log.hugeverbose(*args, extra={"scan_id": self.id}, **kwargs)
        if trace:
            self.trace()

    def info(self, *args, trace=False, **kwargs):
        log.info(*args, extra={"scan_id": self.id}, **kwargs)
        if trace:
            self.trace()

    def hugeinfo(self, *args, trace=False, **kwargs):
        log.hugeinfo(*args, extra={"scan_id": self.id}, **kwargs)
        if trace:
            self.trace()

    def success(self, *args, trace=False, **kwargs):
        log.success(*args, extra={"scan_id": self.id}, **kwargs)
        if trace:
            self.trace()

    def hugesuccess(self, *args, trace=False, **kwargs):
        log.hugesuccess(*args, extra={"scan_id": self.id}, **kwargs)
        if trace:
            self.trace()

    def warning(self, *args, trace=True, **kwargs):
        log.warning(*args, extra={"scan_id": self.id}, **kwargs)
        if trace:
            self.trace()

    def hugewarning(self, *args, trace=True, **kwargs):
        log.hugewarning(*args, extra={"scan_id": self.id}, **kwargs)
        if trace:
            self.trace()

    def error(self, *args, trace=True, **kwargs):
        log.error(*args, extra={"scan_id": self.id}, **kwargs)
        if trace:
            self.trace()

    def trace(self, msg=None):
        if msg is None:
            e_type, e_val, e_traceback = exc_info()
            if e_type is not None:
                log.trace(traceback.format_exc())
        else:
            log.trace(msg)

    def critical(self, *args, trace=True, **kwargs):
        log.critical(*args, extra={"scan_id": self.id}, **kwargs)
        if trace:
            self.trace()

    @property
    def log_level(self):
        """
        Return the current log level, e.g. logging.INFO
        """
        return self.core.logger.log_level

    @property
    def _log_handlers(self):
        if self.__log_handlers is None:
            self.helpers.mkdir(self.home)
            main_handler = logging.handlers.TimedRotatingFileHandler(
                str(self.home / "scan.log"), when="d", interval=1, backupCount=14
            )
            main_handler.addFilter(lambda x: x.levelno != logging.TRACE and x.levelno >= logging.VERBOSE)
            debug_handler = logging.handlers.TimedRotatingFileHandler(
                str(self.home / "debug.log"), when="d", interval=1, backupCount=14
            )
            debug_handler.addFilter(lambda x: x.levelno >= logging.DEBUG)
            self.__log_handlers = [main_handler, debug_handler]
        return self.__log_handlers

    def _start_log_handlers(self):
        # add log handlers
        for handler in self._log_handlers:
            self.core.logger.add_log_handler(handler)
        # temporarily disable main ones
        for handler_name in ("file_main", "file_debug"):
            handler = self.core.logger.log_handlers.get(handler_name, None)
            if handler is not None and handler not in self._log_handler_backup:
                self._log_handler_backup.append(handler)
                self.core.logger.remove_log_handler(handler)

    def _stop_log_handlers(self):
        # remove log handlers
        for handler in self._log_handlers:
            self.core.logger.remove_log_handler(handler)
        # restore main ones
        for handler in self._log_handler_backup:
            self.core.logger.add_log_handler(handler)

    def _fail_setup(self, msg):
        msg = str(msg)
        if self.force_start:
            self.error(msg)
        else:
            msg += " (--force to run module anyway)"
            raise ScanError(msg)

    def _load_modules(self, modules):
        modules = [str(m) for m in modules]
        loaded_modules = {}
        failed = set()
        for module_name, module_class in self.preset.module_loader.load_modules(modules).items():
            if module_class:
                try:
                    loaded_modules[module_name] = module_class(self)
                    self.verbose(f'Loaded module "{module_name}"')
                    continue
                except Exception:
                    self.warning(f"Failed to load module {module_class}")
            else:
                self.warning(f'Failed to load unknown module "{module_name}"')
            failed.add(module_name)
        return loaded_modules, failed

    async def _status_ticker(self, interval=15):
        async with self._acatch():
            while 1:
                await asyncio.sleep(interval)
                self.modules_status(_log=True)

    @contextlib.asynccontextmanager
    async def _acatch(self, context="scan", finally_callback=None, unhandled_is_critical=False):
        """
        Async version of catch()

        async with catch():
            await do_stuff()
        """
        try:
            yield
        except BaseException as e:
            self._handle_exception(e, context=context, unhandled_is_critical=unhandled_is_critical)

    def _handle_exception(self, e, context="scan", finally_callback=None, unhandled_is_critical=False):
        if callable(context):
            context = f"{context.__qualname__}()"
        filename, lineno, funcname = self.helpers.get_traceback_details(e)
        if self.helpers.in_exception_chain(e, (KeyboardInterrupt,)):
            log.debug(f"Interrupted")
            self.stop()
        elif isinstance(e, BrokenPipeError):
            log.debug(f"BrokenPipeError in {filename}:{lineno}:{funcname}(): {e}")
        elif isinstance(e, asyncio.CancelledError):
            raise
        elif isinstance(e, Exception):
            traceback_str = getattr(e, "engine_traceback", None)
            if traceback_str is None:
                traceback_str = traceback.format_exc()
            if unhandled_is_critical:
                log.critical(f"Error in {context}: {filename}:{lineno}:{funcname}(): {e}")
                log.critical(traceback_str)
            else:
                log.error(f"Error in {context}: {filename}:{lineno}:{funcname}(): {e}")
                log.trace(traceback_str)
        if callable(finally_callback):
            finally_callback(e)

    def _make_dummy_module(self, name, _type="scan"):
        """
        Construct a dummy module, for attachment to events
        """
        try:
            return self.dummy_modules[name]
        except KeyError:
            dummy = DummyModule(scan=self, name=name, _type=_type)
            self.dummy_modules[name] = dummy
            return dummy


from bbot.modules.base import BaseModule


class DummyModule(BaseModule):
    _priority = 4

    def __init__(self, *args, **kwargs):
        self._name = kwargs.pop("name")
        self._type = kwargs.pop("_type")
        super().__init__(*args, **kwargs)
