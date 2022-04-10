import logging
from uuid import uuid4
import concurrent.futures
from collections import OrderedDict

from .manager import EventManager
from bbot.core.target import ScanTarget
from bbot.core.configurator import available_modules
from bbot.core.event import make_event, make_event_id
from bbot.core.helpers.helper import ConfigAwareHelper

log = logging.getLogger("bbot.scanner")


class Scanner:
    def __init__(self, *targets, scan_id=None, name=None, modules=None, config=None):
        if modules is None:
            modules = []
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

            self.info(f"Setting up modules")
            setup_futures = dict()
            for module_name, module in self.modules.items():
                future = self._thread_pool.submit(module._setup)
                setup_futures[future] = module_name
            for future in self.helpers.as_completed(setup_futures):
                module_name = setup_futures[future]
                result = future.result()
                if not result == True:
                    self.error(f'Setup failed for module "{module_name}"')
                    self.modules.pop(module_name)

            if not self.modules:
                self.error(f"No modules loaded")
                self._status = "ERROR_FAILED"
                return
            else:
                self.success(f"Successfully set up {len(self.modules):,} modules")

            # distribute seed events
            self.manager.init_events()

            self._status = "RUNNING"
            self.info(f"Starting modules")
            for module_name, module in self.modules.items():
                module.start()
            self.info(f"{len(self.modules):,} modules started")

            self.manager.loop_until_finished()
            failed = False

        except KeyboardInterrupt:
            self.stop()
            failed = False

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

    def stop(self):
        if self._status != "ABORTING":
            self._status = "ABORTING"
            self.warning(f"Aborting scan")
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
