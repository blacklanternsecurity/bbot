import logging
from time import sleep
from pathlib import Path
import concurrent.futures

from . import misc
from .dns import DNSHelper

log = logging.getLogger("bbot.core.helpers")


class ConfigAwareHelper:

    from .web import request, download, validate_url
    from .command import run, run_live
    from .cache import cache_get, cache_put, cache_filename, is_cached
    from . import regexes

    def __init__(self, config, scan=None):
        self.config = config
        self.scan = scan
        self.__thread_pool = None
        self.dns = DNSHelper(self)
        self.bbot_path = Path(__file__).parent.parent.parent.parent
        self.home = Path.home() / ".bbot"
        self.cache_dir = self.home / "cache"

    def submit_task(self, *args, **kwargs):
        return self._thread_pool.submit(*args, **kwargs)

    @property
    def _thread_pool(self):
        if self.scan is None:
            self.__thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.config.get("max_threads", 100))
        else:
            self.__thread_pool = self.scan._thread_pool
        return self.__thread_pool

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
        Allow static functions from .misc to be accessed via ConfigAwareHelper class
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
