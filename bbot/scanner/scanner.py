import logging
import threading
from uuid import uuid4
import concurrent.futures
from collections import OrderedDict

from .manager import EventManager
from bbot.core.target import ScanTarget
from bbot.core.errors import BBOTError, ScanError
from bbot.core.event import make_event, make_event_id
from bbot.core.helpers.helper import ConfigAwareHelper
from bbot.core.configurator import available_modules, available_output_modules

log = logging.getLogger("bbot.scanner")


class Scanner:
    def __init__(
        self, *targets, scan_id=None, name=None, modules=None, output_modules=None, config=None
    ):
        if modules is None:
            modules = []
        if output_modules is None:
            output_modules = ["json"]
        if config is None:
            config = {}

        if scan_id is not None:
            self.id = str(scan_id)
        else:
            self.id = str(uuid4())
        self.config = config
        self._status = "NOT_STARTED"

        self.target = ScanTarget(self, *targets)
        if not self.target:
            self.error(f"No scan targets specified")
        if name is None:
            self.name = str(self.target)
        else:
            self.name = str(name)

        self.manager = EventManager(self)
        self.helpers = ConfigAwareHelper(config=self.config, scan=self)

        # prevent too many brute force modules from running at one time
        # because they can bypass the global thread limit
        self.max_brute_forcers = int(self.config.get("max_brute_forcers", 1))
        self._brute_lock = threading.Semaphore(self.max_brute_forcers)

        # Set up shared thread pool
        self._thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.config.get("max_threads", 100)
        )

        # Load modules
        self.modules = dict()
        self.info(f"Loading {len(modules):,} modules: {','.join(list(modules))}")
        for module_name in [str(m) for m in modules]:

            module_class = available_modules.get(module_name, None)
            if module_class:
                try:
                    self.modules[module_name] = module_class(self)
                    self.verbose(f'Loaded module "{module_name}"')
                except Exception:
                    import traceback

                    self.error(f"Failed to load module {module_class}\n{traceback.format_exc()}")
            else:
                self.error(f'Failed to load unknown module "{module_name}"')

        # Load output modules
        self.info(
            f"Loading {len(output_modules):,} output modules: {','.join(list(output_modules))}"
        )
        for module_name in [str(m) for m in output_modules]:

            module_class = available_output_modules.get(module_name, None)
            if module_class:
                try:
                    self.modules[module_name] = module_class(self)
                    self.verbose(f'Loaded output module "{module_name}"')
                except Exception:
                    import traceback

                    self.error(
                        f"Failed to load output module {module_class}\n{traceback.format_exc()}"
                    )
            else:
                self.error(f'Failed to load unknown output module "{module_name}"')

        self.modules = OrderedDict(
            sorted(self.modules.items(), key=lambda x: getattr(x[-1], "_priority", 0))
        )
        if self.modules:
            self.success(f"Loaded {len(self.modules):,} modules")

    def start(self):

        failed = True

        try:
            self._status = "STARTING"
            self.info(f"Starting scan {self.id}")

            self.setup_modules()

            if not self.modules:
                self.error(f"No modules loaded")
                self._status = "ERROR_FAILED"
                return
            else:
                self.success(f"Successfully set up {len(self.modules):,} modules")

            # distribute seed events
            self.manager.init_events()

            self._status = "RUNNING"
            self.start_modules()
            self.info(f"{len(self.modules):,} modules started")

            self.manager.loop_until_finished()
            failed = False

        except KeyboardInterrupt:
            self.stop()
            failed = False

        except BBOTError as e:
            self.critical(str(e))

        except Exception:
            import traceback

            self.critical(f"Unexpected error during scan:\n{traceback.format_exc()}")
            self._status = "ERROR_FAILED"

        finally:
            # Shut down shared thread pool
            self._thread_pool.shutdown(wait=True)

            # Set status
            if failed:
                self._status = "FAILED"
                self.error(f"Scan {self.id} completed with status {self.status}")
            else:
                if self.status == "STOPPING":
                    self._status = "STOPPED"
                    self.warning(f"Scan {self.id} completed with status {self.status}")
                elif self.status == "ABORTING":
                    self._status = "ABORTED"
                    self.warning(f"Scan {self.id} completed with status {self.status}")
                else:
                    self._status = "FINISHED"
                    self.success(f"Scan {self.id} completed with status {self.status}")

    def start_modules(self):
        self.info(f"Starting modules")
        for module_name, module in self.modules.items():
            module.start()

    def setup_modules(self, remove_failed=True):
        self.info(f"Setting up modules")
        setup_futures = dict()
        for module_name, module in self.modules.items():
            future = self._thread_pool.submit(module._setup)
            setup_futures[future] = module_name
        for future in self.helpers.as_completed(setup_futures):
            module_name = setup_futures[future]
            result = future.result()
            if remove_failed and not result == True:
                self.error(f'Setup failed for module "{module_name}"')
                self.modules.pop(module_name)
        num_output_modules = len([m for m in self.modules.values() if m._type == "output"])
        if num_output_modules < 1:
            raise ScanError("Failed to load output modules. Aborting.")

    def stop(self):
        if self._status != "ABORTING":
            self._status = "ABORTING"
            self.warning(f"Aborting scan")
            for i in range(max(10, self.max_brute_forcers * 10)):
                self._brute_lock.release()
            self.debug(f"Shutting down thread pool")
            self._thread_pool.shutdown(wait=False, cancel_futures=True)

            self.debug(f"Finished shutting down thread pool")
            self.helpers.kill_children()

    @property
    def status(self):
        return self._status

    def make_event(self, *args, **kwargs):
        """
        If data is already an event, simply return it
        Handle dummy event type
        """
        kwargs["scan_id"] = self.id
        return make_event(*args, **kwargs)

    @property
    def log(self):
        if self._log is None:
            self._log = logging.getLogger(f"bbot.agent.scanner")
        return self._log

    @property
    def stopping(self):
        return self.status not in ["RUNNING", "FINISHING"]

    @property
    def root_event(self):
        data = f"SCAN:{self.id}"
        return self.make_event(
            data=data, event_type="SCAN", dummy=True, source=make_event_id(data, "SCAN")
        )

    @property
    def json(self):
        j = dict()
        for i in ("id", "name"):
            v = getattr(self, i, "")
            if v:
                j.update({i: v})
        if self.target:
            j.update({"targets": [str(e.data) for e in self.target]})
        if self.modules:
            j.update({"modules": [str(m) for m in self.modules]})
        # j.update({"config": self.config})
        return j

    def debug(self, *args, **kwargs):
        log.debug(*args, extra={"scan_id": self.id}, **kwargs)

    def verbose(self, *args, **kwargs):
        log.verbose(*args, extra={"scan_id": self.id}, **kwargs)

    def info(self, *args, **kwargs):
        log.info(*args, extra={"scan_id": self.id}, **kwargs)

    def success(self, *args, **kwargs):
        log.success(*args, extra={"scan_id": self.id}, **kwargs)

    def warning(self, *args, **kwargs):
        log.warning(*args, extra={"scan_id": self.id}, **kwargs)

    def error(self, *args, **kwargs):
        log.error(*args, extra={"scan_id": self.id}, **kwargs)

    def critical(self, *args, **kwargs):
        log.critical(*args, extra={"scan_id": self.id}, **kwargs)
