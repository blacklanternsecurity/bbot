import logging
import traceback
import threading
import multiprocessing
from multiprocessing.context import SpawnProcess

from .misc import in_exception_chain


current_process = multiprocessing.current_process()


class BBOTThread(threading.Thread):

    default_name = "default bbot thread"

    def __init__(self, *args, **kwargs):
        self.custom_name = kwargs.pop("custom_name", self.default_name)
        if "daemon" not in kwargs:
            kwargs["daemon"] = True
        super().__init__(*args, **kwargs)

    def run(self):
        from setproctitle import setthreadtitle

        setthreadtitle(str(self.custom_name))
        super().run()


class BBOTProcess(SpawnProcess):

    default_name = "bbot process pool"

    def __init__(self, *args, **kwargs):
        self.log_queue = kwargs.pop("log_queue", None)
        self.log_level = kwargs.pop("log_level", None)
        self.custom_name = kwargs.pop("custom_name", self.default_name)
        super().__init__(*args, **kwargs)
        self.daemon = True

    def run(self):
        """
        A version of Process.run() with BBOT logging and better error handling
        """
        log = logging.getLogger("bbot.core.process")
        try:
            if self.log_level is not None and self.log_queue is not None:
                from bbot.core import CORE

                CORE.logger.setup_queue_handler(self.log_queue, self.log_level)
            if self.custom_name:
                from setproctitle import setproctitle

                setproctitle(str(self.custom_name))
            super().run()
        except BaseException as e:
            if not in_exception_chain(e, (KeyboardInterrupt,)):
                log.warning(f"Error in {self.name}: {e}")
            log.trace(traceback.format_exc())


if current_process.name == "MainProcess":
    # if this is the main bbot process, set the logger and queue for the first time
    from bbot.core import CORE
    from functools import partialmethod

    BBOTProcess.__init__ = partialmethod(
        BBOTProcess.__init__, log_level=CORE.logger.log_level, log_queue=CORE.logger.queue
    )

# this makes our process class the default for process pools, etc.
mp_context = multiprocessing.get_context("spawn")
mp_context.Process = BBOTProcess
