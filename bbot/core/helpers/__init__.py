import logging
from time import sleep
import concurrent.futures

from . import misc
from .misc import *
from . import regexes
from .dns import DNSHelper

log = logging.getLogger("bbot.core.helpers")


class Helpers:

    from .web import request, download

    def __init__(self, config, scan=None):
        self.config = config
        self.scan = scan
        self._thread_pool = None
        self.dns = DNSHelper(self)

    def run_async(self, *args, **kwargs):
        return self.thread_pool.submit(*args, **kwargs)

    @property
    def thread_pool(self):
        if self.scan is None:
            self._thread_pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=self.config.get("max_threads", 100)
            )
        else:
            self._thread_pool = self.scan.thread_pool
        return self._thread_pool

    @staticmethod
    def as_completed(fs):
        fs = list(fs)
        while fs:
            result = False
            for i, f in enumerate(fs):
                if f.done():
                    result = True
                    future = fs.pop(i)
                    if future._state in ("CANCELLED", "CANCELLED_AND_NOTIFIED"):
                        continue
                    yield future
                    break
            if not result:
                sleep(0.05)

    def __getattribute__(self, attr):
        """
        Allow static functions from .misc to be accessed via Helpers class
        """
        try:
            return super().__getattribute__(attr)
        except AttributeError:
            method = getattr(misc, attr, None)
            if method:
                return method
            else:
                method = getattr(self.dns, attr, None)
            if method:
                return method
            else:
                raise
