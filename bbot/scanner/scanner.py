import logging
from contextlib import suppress
from collections import OrderedDict

from .manager import EventManager
from bbot.core.helpers import Helpers
from bbot.core.target import ScanTarget
from bbot.core.threadpool import ThreadPool
from bbot.core.configurator import available_modules

log = logging.getLogger("bbot.scanner")


class Scanner:
    def __init__(self, scan_id, *targets, modules=None, config=None):
        if modules is None:
            modules = []
        if config is None:
            config = {}

        self.id = str(scan_id)
        self.config = config
        self._status = "NOT_STARTED"

        self.target = ScanTarget(*targets)
        if not self.target:
            self.error(f"No scan targets specified")

        self.manager = EventManager(self)
        self.helpers = Helpers(self.config)

        # Set up shared thread pool
        self.shared_thread_pool = ThreadPool(
            threads=config.get("max_threads", 100), name="scanner_shared_thread_pool"
        )

        # Load modules
        self.modules = dict()
        self.info(f"Loading {len(modules):,} modules")
        for module_name in [str(m) for m in modules]:

            module_class = available_modules.get(module_name, None)
            if module_class:
                try:
                    self.modules[module_name] = module_class(self)
                    self.info(f'Loaded module "{module_name}"')
                except Exception:
                    import traceback

                    self.error(
                        f"Failed to load module {module_class}\n{traceback.format_exc()}"
                    )
            else:
                self.error(f'Failed to load unknown module "{module_name}"')
        self.modules = OrderedDict(
            sorted(self.modules.items(), key=lambda x: getattr(x[-1], "priority", 0))
        )
        if self.modules:
            self.success(f"Loaded {len(self.modules):,} modules")

    def start(self):

        failed = True

        try:
            self._status = "STARTING"
            self.info(f"Starting scan {self.id}")

            self.shared_thread_pool.start()

            self.info(f"Setting up modules")
            for module_name, module in self.modules.items():
                try:
                    module.setup()
                except Exception:
                    module.set_error_state()
                    import traceback

                    self.error(
                        f"Failed to setup module {module_name}:\n{traceback.format_exc()}"
                    )
            if not self.modules:
                self.error(f"No modules loaded")
                self._status = "ERROR_FAILED"
                return

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
            with suppress(Exception):
                self.shared_thread_pool.shutdown(wait=True)

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
        self.warning(f"Aborting scan")
        self._status = "ABORTING"
        self.shared_thread_pool.stop = True
        self.helpers.misc.kill_children()

    @property
    def status(self):
        return self._status

    @property
    def log(self):
        if self._log is None:
            self._log = logging.getLogger(f"bbot.agent.scanner")
        return self._log

    @property
    def stopping(self):
        return self.status not in ["RUNNING", "FINISHING"]

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
