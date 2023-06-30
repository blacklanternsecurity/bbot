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

from bbot import config as bbot_config

from .stats import ScanStats
from .target import ScanTarget
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
from bbot.core.logger import init_logging, get_log_level, set_log_level

log = logging.getLogger("bbot.scanner")

init_logging()


class Scanner:
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
        config=None,
        dispatcher=None,
        strict_scope=False,
        force_start=False,
    ):
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
        output_dir = self.config.get("output_dir", "")

        if name is None:
            tries = 0

            while 1:
                if tries > 5:
                    self.name = f"{self.helpers.rand_string(4)}_{self.helpers.rand_string(4)}"
                    break

                self.name = random_name()

                if output_dir:
                    home_path = Path(output_dir).resolve() / self.name
                else:
                    home_path = self.helpers.bbot_home / "scans" / self.name

                if not home_path.exists():
                    break
                tries += 1
        else:
            self.name = str(name)

        if output_dir:
            self.home = Path(output_dir).resolve() / self.name
        else:
            self.home = self.helpers.bbot_home / "scans" / self.name

        self.target = ScanTarget(self, *targets, strict_scope=strict_scope)

        self.modules = OrderedDict({})
        self._scan_modules = modules
        self._internal_modules = list(self._internal_modules())
        self._output_modules = output_modules
        self._modules_loaded = False

        if not whitelist:
            self.whitelist = self.target.copy()
        else:
            self.whitelist = ScanTarget(self, *whitelist, strict_scope=strict_scope)
        if not blacklist:
            blacklist = []
        self.blacklist = ScanTarget(self, *blacklist)

        if dispatcher is None:
            self.dispatcher = Dispatcher()
        else:
            self.dispatcher = dispatcher
        self.dispatcher.set_scan(self)

        self.manager = ScanManager(self)
        self.stats = ScanStats(self)

        # scope distance
        self.scope_search_distance = max(0, int(self.config.get("scope_search_distance", 0)))
        self.dns_search_distance = max(
            self.scope_search_distance, int(self.config.get("scope_dns_search_distance", 2))
        )
        self.scope_report_distance = int(self.config.get("scope_report_distance", 1))

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
        self.manager_worker_loop_tasks = []
        self.init_events_task = None
        self.ticker_task = None
        self.dispatcher_tasks = []

        # multiprocessing thread pool
        try:
            mp.set_start_method("spawn")
        except Exception:
            self.warning(f"Failed to set multiprocessing spawn method. This may negatively affect performance.")
        self.process_pool = ProcessPoolExecutor()

        self._stopping = False

    def _on_keyboard_interrupt(self, loop, event):
        self.stop()

    async def prep(self):
        # event = asyncio.Event()
        # self._loop.add_signal_handler(signal.SIGINT, self._on_keyboard_interrupt, loop, event)

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
            await self.setup_modules()

            self.success(f"Setup succeeded for {len(self.modules):,} modules.")
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
        failed = True
        scan_start_time = datetime.now()
        try:
            await self.prep()

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
            self.manager_worker_loop_tasks = [
                asyncio.create_task(self.manager._worker_loop()) for _ in range(self.max_workers)
            ]

            # distribute seed events
            self.init_events_task = asyncio.create_task(self.manager.init_events())

            self.status = "RUNNING"
            self.start_modules()
            self.verbose(f"{len(self.modules):,} modules started")

            # main scan loop
            while 1:
                # abort if we're aborting
                if self.aborting:
                    self.drain_queues()
                    break

                if "python" in self.modules:
                    events, finish, report = await self.modules["python"].events_waiting()
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
            self.cancel_tasks()
            await self.report()
            await self.cleanup()

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

    def start_modules(self):
        self.verbose(f"Starting module worker loops")
        for module_name, module in self.modules.items():
            module.start()

    async def setup_modules(self, remove_failed=True):
        await self.load_modules()
        self.verbose(f"Setting up modules")
        hard_failed = []
        soft_failed = []

        for task in asyncio.as_completed([asyncio.create_task(m._setup()) for m in self.modules.values()]):
            module_name, status, msg = await task
            if status == True:
                self.debug(f"Setup succeeded for {module_name} ({msg})")
            elif status == False:
                self.error(f"Setup hard-failed for {module_name}: {msg}")
                self.modules[module_name].set_error_state()
                hard_failed.append(module_name)
            else:
                self.warning(f"Setup soft-failed for {module_name}: {msg}")
                soft_failed.append(module_name)
            if not status and remove_failed:
                self.modules.pop(module_name)

        num_output_modules = len([m for m in self.modules.values() if m._type == "output"])
        if num_output_modules < 1:
            raise ScanError("Failed to load output modules. Aborting.")
        total_failed = len(hard_failed + soft_failed)
        if hard_failed:
            msg = f"Setup hard-failed for {len(hard_failed):,} modules ({','.join(hard_failed)})"
            self.fail_setup(msg)
        elif total_failed > 0:
            self.warning(f"Setup failed for {total_failed:,} modules")

    def stop(self):
        if not self._stopping:
            self._stopping = True
            self.status = "ABORTING"
            self.hugewarning(f"Aborting scan")
            self.trace()
            self.cancel_tasks()
            self.drain_queues()
            self.helpers.kill_children()
            self.drain_queues()
            self.helpers.kill_children()

    async def finish(self):
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

    def drain_queues(self):
        # Empty event queues
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

    def cancel_tasks(self):
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
        tasks += self.manager_worker_loop_tasks
        self.helpers.cancel_tasks_sync(tasks)
        # process pool
        self.process_pool.shutdown(cancel_futures=True)

    async def report(self):
        for mod in self.modules.values():
            async with self.acatch(context=mod.report):
                with mod._task_counter:
                    await mod.report()

    async def cleanup(self):
        # clean up modules
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
        Checks whitelist and blacklist, also taking scope_distance into account
        """
        try:
            e = make_event(e, dummy=True)
        except ValidationError:
            return False
        in_scope = e.scope_distance == 0 or self.whitelisted(e)
        return in_scope and not self.blacklisted(e)

    def blacklisted(self, e):
        e = make_event(e, dummy=True)
        return e in self.blacklist

    def whitelisted(self, e):
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
    def log(self):
        if self._log is None:
            self._log = logging.getLogger(f"bbot.agent.scanner")
        return self._log

    @property
    def root_event(self):
        root_event = self.make_event(data=f"{self.name} ({self.id})", event_type="SCAN", dummy=True)
        root_event._id = self.id
        root_event.scope_distance = 0
        root_event._resolved.set()
        root_event.source = root_event
        root_event.module = self.helpers._make_dummy_module(name="TARGET", _type="TARGET")
        return root_event

    @property
    def useragent(self):
        return self.config.get("user_agent", "BBOT")

    @property
    def json(self):
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

    def _internal_modules(self):
        for modname in module_loader.preloaded(type="internal"):
            if self.config.get(modname, True):
                yield modname

    async def load_modules(self):
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
                self.fail_setup(msg)
            modules = sorted([m for m in self._scan_modules if m in succeeded])
            output_modules = sorted([m for m in self._output_modules if m in succeeded])
            internal_modules = sorted([m for m in self._internal_modules if m in succeeded])

            # Load scan modules
            self.verbose(f"Loading {len(modules):,} scan modules: {','.join(modules)}")
            loaded_modules, failed = self._load_modules(modules)
            self.modules.update(loaded_modules)
            if len(failed) > 0:
                msg = f"Failed to load {len(failed):,} scan modules: {','.join(failed)}"
                self.fail_setup(msg)
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
                self.fail_setup(msg)
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
                self.fail_setup(msg)
            if loaded_output_modules:
                self.info(
                    f"Loaded {len(loaded_output_modules):,}/{len(self._output_modules):,} output modules, ({','.join(loaded_output_modules)})"
                )

            self.modules = OrderedDict(sorted(self.modules.items(), key=lambda x: getattr(x[-1], "_priority", 0)))
            self._modules_loaded = True

    def fail_setup(self, msg):
        msg = str(msg)
        if not self.force_start:
            msg += " (--force to run module anyway)"
        if self.force_start:
            self.error(msg)
        else:
            raise ScanError(msg)

    @property
    def log_level(self):
        return get_log_level()

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
        async with self.acatch():
            while 1:
                await asyncio.sleep(interval)
                self.manager.modules_status(_log=True)

    @contextlib.contextmanager
    def catch(self, context="scan", finally_callback=None):
        """
        Handle common errors by stopping scan, logging tracebacks, etc.

        with catch():
            do_stuff()
        """
        try:
            yield
        except BaseException as e:
            self._handle_exception(e, context=context)

    @contextlib.asynccontextmanager
    async def acatch(self, context="scan", finally_callback=None):
        """
        Async version of catch()

        async with catch():
            await do_stuff()
        """
        try:
            yield
        except BaseException as e:
            self._handle_exception(e, context=context)

    def run_in_executor(self, callback, *args, **kwargs):
        """
        Run a synchronous task in the event loop's default thread pool executor
        """
        callback = partial(callback, **kwargs)
        return self._loop.run_in_executor(None, callback, *args)

    def run_in_executor_mp(self, callback, *args, **kwargs):
        """
        Same as run_in_executor() except with a process pool executor
        """
        callback = partial(callback, **kwargs)
        return self._loop.run_in_executor(self.process_pool, callback, *args)

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
            self.helpers.execute_sync_or_async(finally_callback, e)
