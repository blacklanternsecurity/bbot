import re
import sys
import asyncio
import logging
import traceback
import contextlib
from sys import exc_info
from pathlib import Path
import multiprocessing as mp
from datetime import datetime
from functools import partial
from omegaconf import OmegaConf
from collections import OrderedDict
from concurrent.futures import ProcessPoolExecutor

from bbot import __version__
from bbot import config as bbot_config

from .target import Target
from .stats import ScanStats
from .manager import ScanManager
from .dispatcher import Dispatcher
from bbot.modules import module_loader
from bbot.core.event import make_event
from bbot.core.helpers.misc import sha1, rand_string
from bbot.core.helpers.helper import ConfigAwareHelper
from bbot.core.helpers.names_generator import random_name
from bbot.core.helpers.async_helpers import async_to_sync_gen
from bbot.core.configurator.environ import prepare_environment
from bbot.core.errors import BBOTError, ScanError, ValidationError
from bbot.core.logger import (
    init_logging,
    get_log_level,
    set_log_level,
    add_log_handler,
    get_log_handlers,
    remove_log_handler,
)

log = logging.getLogger("bbot.scanner")

init_logging()


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
        target (Target): Target of scan
        config (omegaconf.dictconfig.DictConfig): BBOT config
        whitelist (Target): Scan whitelist (by default this is the same as `target`)
        blacklist (Target): Scan blacklist (this takes ultimate precedence)
        helpers (ConfigAwareHelper): Helper containing various reusable functions, regexes, etc.
        manager (ScanManager): Coordinates and monitors the flow of events between modules during a scan
        dispatcher (Dispatcher): Triggers certain events when the scan `status` changes
        modules (dict): Holds all loaded modules in this format: `{"module_name": Module()}`
        stats (ScanStats): Holds high-level scan statistics such as how many events have been produced and consumed by each module
        home (pathlib.Path): Base output directory of the scan (default: `~/.bbot/scans/<scan_name>`)
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
        whitelist=None,
        blacklist=None,
        scan_id=None,
        name=None,
        modules=None,
        output_modules=None,
        output_dir=None,
        config=None,
        dispatcher=None,
        strict_scope=False,
        force_start=False,
    ):
        """
        Initializes the Scanner class.

        Args:
            *targets (str): Target(s) to scan.
            whitelist (list, optional): Whitelisted target(s) to scan. Defaults to the same as `targets`.
            blacklist (list, optional): Blacklisted target(s). Takes ultimate precedence. Defaults to empty.
            scan_id (str, optional): Unique identifier for the scan. Auto-generates if None.
            name (str, optional): Human-readable name of the scan. Auto-generates if None.
            modules (list[str], optional): List of module names to use during the scan. Defaults to empty list.
            output_modules (list[str], optional): List of output modules to use. Defaults to ['python'].
            output_dir (str or Path, optional): Directory to store scan output. Defaults to BBOT home directory (`~/.bbot`).
            config (dict, optional): Configuration settings. Merged with BBOT config.
            dispatcher (Dispatcher, optional): Dispatcher object to use. Defaults to new Dispatcher.
            strict_scope (bool, optional): If True, only targets explicitly in whitelist are scanned. Defaults to False.
            force_start (bool, optional): If True, allows the scan to start even when module setups hard-fail. Defaults to False.
        """
        if modules is None:
            modules = []
        if output_modules is None:
            output_modules = ["python"]

        if isinstance(modules, str):
            modules = [modules]
        if isinstance(output_modules, str):
            output_modules = [output_modules]

        if config is None:
            config = OmegaConf.create({})
        else:
            config = OmegaConf.create(config)
        self.config = OmegaConf.merge(bbot_config, config)
        prepare_environment(self.config)
        if self.config.get("debug", False):
            set_log_level(logging.DEBUG)

        self.strict_scope = strict_scope
        self.force_start = force_start

        if scan_id is not None:
            self.id = str(scan_id)
        else:
            self.id = f"SCAN:{sha1(rand_string(20)).hexdigest()}"
        self._status = "NOT_STARTED"
        self._status_code = 0

        self.max_workers = max(1, self.config.get("max_threads", 25))
        self.helpers = ConfigAwareHelper(config=self.config, scan=self)

        if name is None:
            tries = 0
            while 1:
                if tries > 5:
                    self.name = f"{self.helpers.rand_string(4)}_{self.helpers.rand_string(4)}"
                    break
                self.name = random_name()
                if output_dir is not None:
                    home_path = Path(output_dir).resolve() / self.name
                else:
                    home_path = self.helpers.bbot_home / "scans" / self.name
                if not home_path.exists():
                    break
                tries += 1
        else:
            self.name = str(name)

        if output_dir is not None:
            self.home = Path(output_dir).resolve() / self.name
        else:
            self.home = self.helpers.bbot_home / "scans" / self.name

        self.target = Target(self, *targets, strict_scope=strict_scope, make_in_scope=True)

        self.modules = OrderedDict({})
        self._scan_modules = modules
        self._internal_modules = list(self._internal_modules())
        self._output_modules = output_modules
        self._modules_loaded = False

        if not whitelist:
            self.whitelist = self.target.copy()
        else:
            self.whitelist = Target(self, *whitelist, strict_scope=strict_scope)
        if not blacklist:
            blacklist = []
        self.blacklist = Target(self, *blacklist)

        if dispatcher is None:
            self.dispatcher = Dispatcher()
        else:
            self.dispatcher = dispatcher
        self.dispatcher.set_scan(self)

        self.manager = ScanManager(self)
        self.stats = ScanStats(self)

        # scope distance
        self.scope_search_distance = max(0, int(self.config.get("scope_search_distance", 0)))
        self.scope_dns_search_distance = max(
            self.scope_search_distance, int(self.config.get("scope_dns_search_distance", 1))
        )
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
        self._cleanedup = False

        self.__loop = None
        self._manager_worker_loop_tasks = []
        self.init_events_task = None
        self.ticker_task = None
        self.dispatcher_tasks = []

        # multiprocessing thread pool
        try:
            mp.set_start_method("spawn")
        except Exception:
            self.warning(f"Failed to set multiprocessing spawn method. This may negatively affect performance.")
        # we spawn 1 fewer processes than cores
        # this helps to avoid locking up the system or competing with the main python process for cpu time
        num_processes = max(1, mp.cpu_count() - 1)
        self.process_pool = ProcessPoolExecutor(max_workers=num_processes)

        self._stopping = False

        self._dns_regexes = None
        self.__log_handlers = None
        self._log_handler_backup = []

    def _on_keyboard_interrupt(self, loop, event):
        self.stop()

    async def _prep(self):
        """
        Calls .load_modules() and .setup_modules() in preparation for a scan
        """

        self.helpers.mkdir(self.home)
        if not self._prepped:
            start_msg = f"Scan with {len(self._scan_modules):,} modules seeded with {len(self.target):,} targets"
            details = []
            if self.whitelist != self.target:
                details.append(f"{len(self.whitelist):,} in whitelist")
            if self.blacklist:
                details.append(f"{len(self.blacklist):,} in blacklist")
            if details:
                start_msg += f" ({', '.join(details)})"
            self.hugeinfo(start_msg)

            await self.load_modules()

            self.info(f"Setting up modules...")
            succeeded, hard_failed, soft_failed = await self.setup_modules()

            num_output_modules = len([m for m in self.modules.values() if m._type == "output"])
            if num_output_modules < 1:
                raise ScanError("Failed to load output modules. Aborting.")
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
            log.verbose(f'Ran BBOT {__version__} at {scan_start_time}, command: {" ".join(sys.argv)}')

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

            # start manager worker loops
            self._manager_worker_loop_tasks = [
                asyncio.create_task(self.manager._worker_loop()) for _ in range(self.max_workers)
            ]

            # distribute seed events
            self.init_events_task = asyncio.create_task(self.manager.init_events())

            self.status = "RUNNING"
            self._start_modules()
            self.verbose(f"{len(self.modules):,} modules started")

            # main scan loop
            while 1:
                # abort if we're aborting
                if self.aborting:
                    self._drain_queues()
                    break

                if "python" in self.modules:
                    events, finish = await self.modules["python"]._events_waiting()
                    for e in events:
                        yield e

                # if initialization finished and the scan is no longer active
                if self._finished_init and not self.manager.active:
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
        for module_name, module in self.modules.items():
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

        If any modules fail to load or their dependencies fail to install, a ScanError will be raised (unless `self.force_start` is set to True).

        Attributes:
            succeeded, failed (tuple): A tuple containing lists of modules that succeeded or failed during the dependency installation.
            loaded_modules, loaded_internal_modules, loaded_output_modules (dict): Dictionaries of successfully loaded modules.
            failed, failed_internal, failed_output (list): Lists of module names that failed to load.

        Raises:
            ScanError: If any module dependencies fail to install or modules fail to load, and if self.force_start is False.

        Returns:
            None

        Note:
            After all modules are loaded, they are sorted by `_priority` and stored in the `modules` dictionary.
        """
        if not self._modules_loaded:
            all_modules = list(set(self._scan_modules + self._output_modules + self._internal_modules))
            if not all_modules:
                self.warning(f"No modules to load")
                return

            if not self._scan_modules:
                self.warning(f"No scan modules to load")

            # install module dependencies
            succeeded, failed = await self.helpers.depsinstaller.install(
                *self._scan_modules, *self._output_modules, *self._internal_modules
            )
            if failed:
                msg = f"Failed to install dependencies for {len(failed):,} modules: {','.join(failed)}"
                self._fail_setup(msg)
            modules = sorted([m for m in self._scan_modules if m in succeeded])
            output_modules = sorted([m for m in self._output_modules if m in succeeded])
            internal_modules = sorted([m for m in self._internal_modules if m in succeeded])

            # Load scan modules
            self.verbose(f"Loading {len(modules):,} scan modules: {','.join(modules)}")
            loaded_modules, failed = self._load_modules(modules)
            self.modules.update(loaded_modules)
            if len(failed) > 0:
                msg = f"Failed to load {len(failed):,} scan modules: {','.join(failed)}"
                self._fail_setup(msg)
            if loaded_modules:
                self.info(
                    f"Loaded {len(loaded_modules):,}/{len(self._scan_modules):,} scan modules ({','.join(loaded_modules)})"
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
                    f"Loaded {len(loaded_internal_modules):,}/{len(self._internal_modules):,} internal modules ({','.join(loaded_internal_modules)})"
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
                    f"Loaded {len(loaded_output_modules):,}/{len(self._output_modules):,} output modules, ({','.join(loaded_output_modules)})"
                )

            self.modules = OrderedDict(sorted(self.modules.items(), key=lambda x: getattr(x[-1], "_priority", 0)))
            self._modules_loaded = True

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
        if self.manager._new_activity:
            self.manager._new_activity = False
            self.status = "FINISHING"
            # Trigger .finished() on every module and start over
            log.info("Finishing scan")
            finished_event = self.make_event("FINISHED", "FINISHED", dummy=True)
            for module in self.modules.values():
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
        with contextlib.suppress(asyncio.queues.QueueEmpty):
            while 1:
                self.manager.incoming_event_queue.get_nowait()
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
        for mod in self.modules.values():
            await mod._cleanup()
        if not self._cleanedup:
            self._cleanedup = True
            with contextlib.suppress(Exception):
                self.home.rmdir()
            self.helpers.clean_old_scans()

    def in_scope(self, e):
        """
        Check whether a hostname, url, IP, etc. is in scope.
        Accepts either events or string data.

        Checks whitelist and blacklist.
        If `e` is an event and its scope distance is zero, it will be considered in-scope.

        Examples:
            Check if a URL is in scope:
            >>> scan.in_scope("http://www.evilcorp.com")
            True
        """
        try:
            e = make_event(e, dummy=True)
        except ValidationError:
            return False
        in_scope = e.scope_distance == 0 or self.whitelisted(e)
        return in_scope and not self.blacklisted(e)

    def blacklisted(self, e):
        """
        Check whether a hostname, url, IP, etc. is blacklisted.
        """
        e = make_event(e, dummy=True)
        return e in self.blacklist

    def whitelisted(self, e):
        """
        Check whether a hostname, url, IP, etc. is whitelisted.
        """
        e = make_event(e, dummy=True)
        return e in self.whitelist

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
        root_event._resolved.set()
        root_event.source = root_event
        root_event.module = self.helpers._make_dummy_module(name="TARGET", _type="TARGET")
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

    def trace(self):
        e_type, e_val, e_traceback = exc_info()
        if e_type is not None:
            log.trace(traceback.format_exc())

    def critical(self, *args, trace=True, **kwargs):
        log.critical(*args, extra={"scan_id": self.id}, **kwargs)
        if trace:
            self.trace()

    @property
    def log_level(self):
        """
        Return the current log level, e.g. logging.INFO
        """
        return get_log_level()

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
            add_log_handler(handler)
        # temporarily disable main ones
        for handler_name in ("file_main", "file_debug"):
            handler = get_log_handlers().get(handler_name, None)
            if handler is not None and handler not in self._log_handler_backup:
                self._log_handler_backup.append(handler)
                remove_log_handler(handler)

    def _stop_log_handlers(self):
        # remove log handlers
        for handler in self._log_handlers:
            remove_log_handler(handler)
        # restore main ones
        for handler in self._log_handler_backup:
            add_log_handler(handler)

    def _internal_modules(self):
        for modname in module_loader.preloaded(type="internal"):
            if self.config.get(modname, True):
                yield modname

    def _fail_setup(self, msg):
        msg = str(msg)
        if not self.force_start:
            msg += " (--force to run module anyway)"
        if self.force_start:
            self.error(msg)
        else:
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
        for module_name, module_class in module_loader.load_modules(modules).items():
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
                self.manager.modules_status(_log=True)

    @contextlib.asynccontextmanager
    async def _acatch(self, context="scan", finally_callback=None):
        """
        Async version of catch()

        async with catch():
            await do_stuff()
        """
        try:
            yield
        except BaseException as e:
            self._handle_exception(e, context=context)

    def _handle_exception(self, e, context="scan", finally_callback=None):
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
            log.error(f"Error in {context}: {filename}:{lineno}:{funcname}(): {e}")
            log.trace(traceback.format_exc())
        if callable(finally_callback):
            finally_callback(e)
