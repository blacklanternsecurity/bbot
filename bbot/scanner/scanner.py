import re
import sys
import asyncio
import logging
import traceback
import contextlib
from pathlib import Path
from sys import exc_info
import multiprocessing as mp
from datetime import datetime
from functools import partial
from collections import OrderedDict
from concurrent.futures import ProcessPoolExecutor

from bbot import __version__


from .preset import Preset
from .stats import ScanStats
from .dispatcher import Dispatcher
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
        >>> my_scan = Scanner("evilcorp.com", "1.2.3.0/24", modules=["nmap", "sslcert", "httpx"])

        Create scan with custom config:
        >>> config = {"http_proxy": "http://127.0.0.1:8080", "modules": {"nmap": {"top_ports": 2000}}}
        >>> my_scan = Scanner("www.evilcorp.com", modules=["nmap", "httpx"], config=config)

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
            *kwargs (list[str], optional): Additional keyword arguments (passed through to `Preset`).
        """
        if scan_id is not None:
            self.id = str(id)
        else:
            self.id = f"SCAN:{sha1(rand_string(20)).hexdigest()}"

        preset = kwargs.pop("preset", None)
        kwargs["_log"] = True
        if preset is None:
            preset = Preset(*targets, **kwargs)
        else:
            if not isinstance(preset, Preset):
                raise ValidationError(f'Preset must be of type Preset, not "{type(preset).__name__}"')
        self.preset = preset.bake()
        self.preset.scan = self

        # scan name
        if preset.scan_name is None:
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
            scan_name = str(preset.scan_name)
        self.name = scan_name

        # scan output dir
        if preset.output_dir is not None:
            self.home = Path(preset.output_dir).resolve() / self.name
        else:
            self.home = self.preset.bbot_home / "scans" / self.name

        self._status = "NOT_STARTED"
        self._status_code = 0

        self.max_workers = max(1, self.config.get("manager_tasks", 5))

        self.modules = OrderedDict({})
        self._modules_loaded = False
        self.dummy_modules = {}

        if dispatcher is None:
            self.dispatcher = Dispatcher()
        else:
            self.dispatcher = dispatcher
        self.dispatcher.set_scan(self)

        self.stats = ScanStats(self)

        # scope distance
        self.scope_search_distance = max(0, int(self.config.get("scope_search_distance", 0)))
        self.scope_report_distance = int(self.config.get("scope_report_distance", 1))

        # url file extensions
        self.url_extension_blacklist = set(e.lower() for e in self.config.get("url_extension_blacklist", []))
        self.url_extension_httpx_only = set(e.lower() for e in self.config.get("url_extension_httpx_only", []))

        # custom HTTP headers warning
        self.custom_http_headers = self.config.get("http_headers", {})
        if self.custom_http_headers:
            self.warning(
                "You have enabled custom HTTP headers. These will be attached to all in-scope requests and all requests made by httpx."
            )

        # how often to print scan status
        self.status_frequency = self.config.get("status_frequency", 15)

        self._prepped = False
        self._finished_init = False
        self._new_activity = False
        self._cleanedup = False

        self.__loop = None
        self._manager_worker_loop_tasks = []
        self.init_events_task = None
        self.ticker_task = None
        self.dispatcher_tasks = []

        # multiprocessing thread pool
        start_method = mp.get_start_method()
        if start_method != "spawn":
            self.warning(f"Multiprocessing spawn method is set to {start_method}.")

        # we spawn 1 fewer processes than cores
        # this helps to avoid locking up the system or competing with the main python process for cpu time
        num_processes = max(1, mp.cpu_count() - 1)
        self.process_pool = ProcessPoolExecutor(max_workers=num_processes)

        self._stopping = False

        self._dns_regexes = None
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
        failed = True
        scan_start_time = datetime.now()
        try:
            await self._prep()

            self._start_log_handlers()
            self.trace(f'Ran BBOT {__version__} at {scan_start_time}, command: {" ".join(sys.argv)}')

            if not self.target:
                self.warning(f"No scan targets specified")

            # start status ticker
            self.ticker_task = asyncio.create_task(self._status_ticker(self.status_frequency))

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
            self.init_events_task = asyncio.create_task(self.ingress_module.init_events(self.target.events))

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

                # break if initialization finished and the scan is no longer active
                if self._finished_init and self.modules_finished:
                    new_activity = await self.finish()
                    if not new_activity:
                        break

                await asyncio.sleep(0.1)

            failed = False

        except BaseException as e:
            exception_chain = self.helpers.get_exception_chain(e)
            if any(isinstance(exc, (KeyboardInterrupt, asyncio.CancelledError)) for exc in exception_chain):
                self.stop()
                failed = False
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
            self._cancel_tasks()
            await self._report()
            await self._cleanup()

            log_fn = self.hugesuccess
            if self.status == "ABORTING":
                self.status = "ABORTED"
                log_fn = self.hugewarning
            elif failed:
                self.status = "FAILED"
                log_fn = self.critical
            else:
                self.status = "FINISHED"

            scan_run_time = datetime.now() - scan_start_time
            scan_run_time = self.helpers.human_timedelta(scan_run_time)
            log_fn(f"Scan {self.name} completed in {scan_run_time} with status {self.status}")

            await self.dispatcher.on_finish(self)

            self._stop_log_handlers()

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
            module_name, status, msg = await task
            if status == True:
                self.debug(f"Setup succeeded for {module_name} ({msg})")
                succeeded.append(module_name)
            elif status == False:
                self.warning(f"Setup hard-failed for {module_name}: {msg}")
                self.modules[module_name].set_error_state()
                hard_failed.append(module_name)
            else:
                self.info(f"Setup soft-failed for {module_name}: {msg}")
                soft_failed.append(module_name)
            if not status and remove_failed:
                self.modules.pop(module_name)

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

            # builtin hook modules
            self.ingress_module = ScanIngress(self)
            self.egress_module = ScanEgress(self)
            self.modules[self.ingress_module.name] = self.ingress_module
            self.modules[self.egress_module.name] = self.egress_module

            # sort modules by priority
            self.modules = OrderedDict(sorted(self.modules.items(), key=lambda x: getattr(x[-1], "priority", 3)))

            # hook modules get sewn together like human centipede
            self.hook_modules = [m for m in self.modules.values() if m._hook]
            for i, hook_module in enumerate(self.hook_modules[:-1]):
                next_hook_module = self.hook_modules[i + 1]
                self.debug(
                    f"Setting hook module {hook_module.name}.outgoing_event_queue to next hook module {next_hook_module.name}.incoming_event_queue"
                )
                hook_module._outgoing_event_queue = next_hook_module.incoming_event_queue

            self._modules_loaded = True

    @property
    def modules_finished(self):
        finished_modules = [m.finished for m in self.modules.values()]
        return all(finished_modules)

    def kill_module(self, module_name, message=None):
        from signal import SIGINT

        module = self.modules[module_name]
        module.set_error_state(message=message, clear_outgoing_queue=True)
        for proc in module._proc_tracker:
            with contextlib.suppress(Exception):
                proc.send_signal(SIGINT)
        self.helpers.cancel_tasks_sync(module._tasks)

    @property
    def queued_event_types(self):
        event_types = {}
        queues = set()

        for module in self.modules.values():
            queues.add(module.incoming_event_queue)
            queues.add(module.outgoing_event_queue)

        for q in queues:
            for event, _ in q._queue:
                event_type = getattr(event, "type", None)
                if event_type is not None:
                    try:
                        event_types[event_type] += 1
                    except KeyError:
                        event_types[event_type] = 1

        return event_types

    def modules_status(self, _log=False):
        finished = True
        status = {"modules": {}}

        sorted_modules = []
        for module_name, module in self.modules.items():
            # if module_name.startswith("_"):
            #     continue
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

            queued_events_by_type = [(k, v) for k, v in self.queued_event_types.items() if v > 0]
            if queued_events_by_type:
                queued_events_by_type.sort(key=lambda x: x[-1], reverse=True)
                queued_events_by_type_str = ", ".join(f"{m}: {t:,}" for m, t in queued_events_by_type)
                num_queued_events = sum(v for k, v in queued_events_by_type)
                self.info(f"{self.name}: {num_queued_events:,} events in queue ({queued_events_by_type_str})")
            else:
                self.info(f"{self.name}: No events in queue")

            if self.log_level <= logging.DEBUG:
                # status debugging
                scan_active_status = []
                scan_active_status.append(f"scan._finished_init: {self._finished_init}")
                scan_active_status.append(f"scan.modules_finished: {self.modules_finished}")
                for m in sorted_modules:
                    running = m.running
                    scan_active_status.append(f"    {m}.finished: {m.finished}")
                    scan_active_status.append(f"        running: {running}")
                    if running:
                        scan_active_status.append(f"        tasks:")
                        for task in list(m._task_counter.tasks.values()):
                            scan_active_status.append(f"            - {task}:")
                    scan_active_status.append(f"        incoming_queue_size: {m.num_incoming_events}")
                    scan_active_status.append(f"        outgoing_queue_size: {m.outgoing_event_queue.qsize()}")
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
            self.hugewarning(f"Aborting scan")
            self.trace()
            self._cancel_tasks()
            self._drain_queues()
            self.helpers.kill_children()
            self._drain_queues()
            self.helpers.kill_children()

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
        # Return False if no new events were generated since last time
        self.verbose("Completed final finish()")
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
                    if module.incoming_event_queue:
                        module.incoming_event_queue.get_nowait()
            with contextlib.suppress(asyncio.queues.QueueEmpty):
                while 1:
                    if module.outgoing_event_queue:
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
        self.process_pool.shutdown(cancel_futures=True)

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
        self.status = "CLEANING_UP"
        # clean up dns engine
        self.helpers.dns.cleanup()
        # clean up modules
        for mod in self.modules.values():
            await mod._cleanup()
        # clean up self
        if not self._cleanedup:
            self._cleanedup = True
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
                        asyncio.create_task(self.dispatcher.catch(self.dispatcher.on_status, self._status, self.id))
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
              "source": "SCAN:1188928d942ace8e3befae0bdb9c3caa22705f54",
              "tags": [
                "distance-0"
              ],
              "module": "TARGET",
              "module_sequence": "TARGET"
            }
            ```
        """
        root_event = self.make_event(data=f"{self.name} ({self.id})", event_type="SCAN", dummy=True)
        root_event._id = self.id
        root_event.scope_distance = 0
        root_event.source = root_event
        root_event.module = self._make_dummy_module(name="TARGET", _type="TARGET")
        return root_event

    def run_in_executor(self, callback, *args, **kwargs):
        """
        Run a synchronous task in the event loop's default thread pool executor

        Examples:
            Execute callback:
            >>> result = await self.scan.run_in_executor(callback_fn, arg1, arg2)
        """
        callback = partial(callback, **kwargs)
        return self._loop.run_in_executor(None, callback, *args)

    def run_in_executor_mp(self, callback, *args, **kwargs):
        """
        Same as run_in_executor() except with a process pool executor
        Use only in cases where callback is CPU-bound

        Examples:
            Execute callback:
            >>> result = await self.scan.run_in_executor_mp(callback_fn, arg1, arg2)
        """
        callback = partial(callback, **kwargs)
        return self._loop.run_in_executor(self.process_pool, callback, *args)

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
            dns_targets = set(t.host for t in self.target if t.host and isinstance(t.host, str))
            dns_whitelist = set(t.host for t in self.whitelist if t.host and isinstance(t.host, str))
            dns_targets.update(dns_whitelist)
            dns_targets = sorted(dns_targets, key=len)
            dns_targets_set = set()
            dns_regexes = []
            for t in dns_targets:
                if not any(x in dns_targets_set for x in self.helpers.domain_parents(t, include_self=True)):
                    dns_targets_set.add(t)
                    dns_regexes.append(re.compile(r"((?:(?:[\w-]+)\.)+" + re.escape(t) + ")", re.I))
            self._dns_regexes = dns_regexes

        return self._dns_regexes

    @property
    def useragent(self):
        """
        Convenient shortcut to the HTTP user-agent configured for the scan
        """
        return self.config.get("user_agent", "BBOT")

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
        if self.target:
            j.update({"targets": [str(e.data) for e in self.target]})
        if self.whitelist:
            j.update({"whitelist": [str(e.data) for e in self.whitelist]})
        if self.blacklist:
            j.update({"blacklist": [str(e.data) for e in self.blacklist]})
        if self.modules:
            j.update({"modules": [str(m) for m in self.modules]})
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
            main_handler.addFilter(
                lambda x: x.levelno not in (logging.STDOUT, logging.TRACE) and x.levelno >= logging.VERBOSE
            )
            debug_handler = logging.handlers.TimedRotatingFileHandler(
                str(self.home / "debug.log"), when="d", interval=1, backupCount=14
            )
            debug_handler.addFilter(lambda x: x.levelno != logging.STDOUT and x.levelno >= logging.DEBUG)
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

    @property
    def _loop(self):
        if self.__loop is None:
            self.__loop = asyncio.get_event_loop()
        return self.__loop

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
        exception_chain = self.helpers.get_exception_chain(e)
        if any(isinstance(exc, KeyboardInterrupt) for exc in exception_chain):
            log.debug(f"Interrupted")
            self.stop()
        elif isinstance(e, BrokenPipeError):
            log.debug(f"BrokenPipeError in {filename}:{lineno}:{funcname}(): {e}")
        elif isinstance(e, asyncio.CancelledError):
            raise
        elif isinstance(e, Exception):
            if unhandled_is_critical:
                log.critical(f"Error in {context}: {filename}:{lineno}:{funcname}(): {e}")
                log.critical(traceback.format_exc())
            else:
                log.error(f"Error in {context}: {filename}:{lineno}:{funcname}(): {e}")
                log.trace(traceback.format_exc())
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

    def _make_dummy_module_dns(self, name):
        try:
            dummy_module = self.dummy_modules[name]
        except KeyError:
            dummy_module = self._make_dummy_module(name=name, _type="DNS")
            dummy_module.suppress_dupes = False
            self.dummy_modules[name] = dummy_module
        return dummy_module


from bbot.modules.base import BaseModule


class DummyModule(BaseModule):
    _priority = 4

    def __init__(self, *args, **kwargs):
        self._name = kwargs.pop("name")
        self._type = kwargs.pop("_type")
        super().__init__(*args, **kwargs)
