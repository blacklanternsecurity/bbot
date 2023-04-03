import logging
import threading
import traceback
from sys import exc_info
from pathlib import Path
import concurrent.futures
from datetime import datetime
from omegaconf import OmegaConf
from contextlib import suppress
from collections import OrderedDict, deque

from bbot import config as bbot_config

from .stats import ScanStats
from .target import ScanTarget
from .manager import ScanManager
from .dispatcher import Dispatcher
from bbot.modules import module_loader
from bbot.core.event import make_event
from bbot.core.helpers.misc import sha1, rand_string
from bbot.core.helpers.helper import ConfigAwareHelper
from bbot.core.logger import init_logging, get_log_level
from bbot.core.helpers.names_generator import random_name
from bbot.core.configurator.environ import prepare_environment
from bbot.core.helpers.threadpool import ThreadPoolWrapper, BBOTThreadPoolExecutor
from bbot.core.errors import BBOTError, ScanError, ScanCancelledError, ValidationError

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

        self.strict_scope = strict_scope
        self.force_start = force_start

        if scan_id is not None:
            self.id = str(scan_id)
        else:
            self.id = f"SCAN:{sha1(rand_string(20)).hexdigest()}"
        self._status = "NOT_STARTED"
        self._status_code = 0

        # Set up thread pools
        max_workers = max(1, self.config.get("max_threads", 25))
        # Shared thread pool, for module use
        self._thread_pool = BBOTThreadPoolExecutor(max_workers=max_workers)
        # Event thread pool, for event emission
        self._event_thread_pool = ThreadPoolWrapper(
            BBOTThreadPoolExecutor(max_workers=max_workers * 2), qsize=max_workers
        )
        # Internal thread pool, for handle_event(), module setup, cleanup callbacks, etc.
        self._internal_thread_pool = ThreadPoolWrapper(BBOTThreadPoolExecutor(max_workers=max_workers))
        self.process_pool = ThreadPoolWrapper(concurrent.futures.ProcessPoolExecutor())
        self.helpers = ConfigAwareHelper(config=self.config, scan=self)
        self.pools = {
            "process_pool": self.process_pool,
            "internal_thread_pool": self._internal_thread_pool,
            "dns_thread_pool": self.helpers.dns._thread_pool,
            "event_thread_pool": self._event_thread_pool,
            "main_thread_pool": self._thread_pool,
        }
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

        self._prepped = False
        self._thread_pools_shutdown = False
        self._thread_pools_shutdown_threads = []
        self._cleanedup = False

    def prep(self):
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

            self.load_modules()

            self.info(f"Setting up modules...")
            self.setup_modules()

            self.success(f"Setup succeeded for {len(self.modules):,} modules.")
            self._prepped = True

    def start_without_generator(self):
        deque(self.start(), maxlen=0)

    def start(self):
        self.prep()

        failed = True

        if not self.target:
            self.warning(f"No scan targets specified")

        scan_start_time = datetime.now()
        try:
            self.status = "STARTING"

            if not self.modules:
                self.error(f"No modules loaded")
                self.status = "FAILED"
                return
            else:
                self.hugesuccess(f"Starting scan {self.name}")

            if self.stopping:
                return

            # distribute seed events
            self.manager.init_events()

            if self.stopping:
                return

            self.status = "RUNNING"
            self.start_modules()
            self.verbose(f"{len(self.modules):,} modules started")

            if self.stopping:
                return

            yield from self.manager.loop_until_finished()
            failed = False

        except KeyboardInterrupt:
            self.stop()
            failed = False

        except ScanCancelledError:
            self.debug("Scan cancelled")

        except ScanError as e:
            self.error(f"{e}")

        except BBOTError as e:
            self.critical(f"Error during scan: {e}")
            self.trace()

        except Exception:
            self.critical(f"Unexpected error during scan:\n{traceback.format_exc()}")

        finally:
            self.cleanup()
            self.shutdown_threadpools()
            while 1:
                for t in self._thread_pools_shutdown_threads:
                    t.join(timeout=1)
                    if t.is_alive():
                        try:
                            pool = t._args[0]
                            for s in pool.threads_status:
                                self.debug(s)
                        except AttributeError:
                            continue
                if not any(t.is_alive() for t in self._thread_pools_shutdown_threads):
                    self.debug("Finished shutting down thread pools")
                    break

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

            self.dispatcher.on_finish(self)

    def start_modules(self):
        self.verbose(f"Starting module threads")
        for module_name, module in self.modules.items():
            module.start()

    def setup_modules(self, remove_failed=True):
        self.load_modules()
        self.verbose(f"Setting up modules")
        hard_failed = []
        soft_failed = []
        setup_futures = dict()

        for module_name, module in self.modules.items():
            future = self._internal_thread_pool.submit_task(module._setup)
            setup_futures[future] = module_name
        for future in self.helpers.as_completed(setup_futures):
            module_name = setup_futures[future]
            status, msg = future.result()
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

    def stop(self, wait=False):
        if self.status != "ABORTING":
            self.status = "ABORTING"
            self.hugewarning(f"Aborting scan")
            self.helpers.kill_children()
            self.shutdown_threadpools()
            self.helpers.kill_children()

    def shutdown_threadpools(self):
        if not self._thread_pools_shutdown:
            self._thread_pools_shutdown = True

            def shutdown_pool(pool, pool_name, **kwargs):
                self.debug(f"Shutting down {pool_name} with kwargs={kwargs}")
                pool.shutdown(**kwargs)
                self.debug(f"Finished shutting down {pool_name} with kwargs={kwargs}")

            self.debug(f"Shutting down thread pools")
            for pool_name, pool in self.pools.items():
                t = threading.Thread(
                    target=shutdown_pool,
                    args=(pool, pool_name),
                    kwargs={"wait": True, "cancel_futures": True},
                    daemon=True,
                )
                t.start()
                self._thread_pools_shutdown_threads.append(t)

    def cleanup(self):
        # clean up modules
        self.status = "CLEANING_UP"
        for mod in self.modules.values():
            mod._cleanup()
        if not self._cleanedup:
            self._cleanedup = True
            with suppress(Exception):
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
                self._status = status
                self._status_code = self._status_codes[status]
                self.dispatcher.on_status(self._status, self.id)
        else:
            self.debug(f'Attempt to set invalid status "{status}" on scan')

    @property
    def status_detailed(self):
        event_threadpool_tasks = self._event_thread_pool.num_tasks
        internal_tasks = self._internal_thread_pool.num_tasks
        process_tasks = self.process_pool.num_tasks
        total_tasks = event_threadpool_tasks + internal_tasks + process_tasks
        status = {
            "queued_tasks": {
                "internal": internal_tasks,
                "process": process_tasks,
                "event": event_threadpool_tasks,
                "total": total_tasks,
            },
        }
        return status

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

    def debug(self, *args, **kwargs):
        log.debug(*args, extra={"scan_id": self.id}, **kwargs)

    def verbose(self, *args, **kwargs):
        log.verbose(*args, extra={"scan_id": self.id}, **kwargs)

    def hugeverbose(self, *args, **kwargs):
        log.hugeverbose(*args, extra={"scan_id": self.id}, **kwargs)

    def info(self, *args, **kwargs):
        log.info(*args, extra={"scan_id": self.id}, **kwargs)

    def hugeinfo(self, *args, **kwargs):
        log.hugeinfo(*args, extra={"scan_id": self.id}, **kwargs)

    def success(self, *args, **kwargs):
        log.success(*args, extra={"scan_id": self.id}, **kwargs)

    def hugesuccess(self, *args, **kwargs):
        log.hugesuccess(*args, extra={"scan_id": self.id}, **kwargs)

    def warning(self, *args, **kwargs):
        log.warning(*args, extra={"scan_id": self.id}, **kwargs)
        self.trace()

    def hugewarning(self, *args, **kwargs):
        log.hugewarning(*args, extra={"scan_id": self.id}, **kwargs)
        self.trace()

    def error(self, *args, **kwargs):
        log.error(*args, extra={"scan_id": self.id}, **kwargs)
        self.trace()

    def trace(self):
        e_type, e_val, e_traceback = exc_info()
        if e_type is not None:
            log.trace(traceback.format_exc())

    def critical(self, *args, **kwargs):
        log.critical(*args, extra={"scan_id": self.id}, **kwargs)

    def _internal_modules(self):
        for modname in module_loader.preloaded(type="internal"):
            if self.config.get(modname, True):
                yield modname

    def load_modules(self):
        if not self._modules_loaded:
            all_modules = list(set(self._scan_modules + self._output_modules + self._internal_modules))
            if not all_modules:
                self.warning(f"No modules to load")
                return

            if not self._scan_modules:
                self.warning(f"No scan modules to load")

            # install module dependencies
            succeeded, failed = self.helpers.depsinstaller.install(
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
