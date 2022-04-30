import atexit
import shutil
import logging
from time import sleep
from pathlib import Path
import concurrent.futures
from threading import Lock

from . import misc
from .dns import DNSHelper
from .wordcloud import WordCloud
from ..errors import ScanCancelledError

log = logging.getLogger("bbot.core.helpers")


class ConfigAwareHelper:

    from .web import request, download, validate_url
    from .command import run, run_live, tempfile, feed_pipe, _feed_pipe
    from .cache import cache_get, cache_put, cache_filename, is_cached
    from . import regexes

    def __init__(self, config, scan=None):
        self.config = config
        self.scan = scan
        self.__thread_pool = None
        self.dns = DNSHelper(self)
        self.home = Path(self.config.get("bbot_home", "~/.bbot")).expanduser().resolve()
        self.cache_dir = self.home / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir = self.home / "temp"
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        atexit.register(self.empty_temp_dir)
        # holds requests CachedSession() objects for duration of scan
        self.cache_sessions = dict()
        self._futures = set()
        self._future_lock = Lock()

        self.word_cloud = WordCloud(self)

    @property
    def num_queued_tasks(self):
        queued_futures = set()
        with self._future_lock:
            for f in self._futures:
                if not f.done():
                    queued_futures.add(f)
            self._futures = queued_futures
        num_queued_tasks = len(queued_futures)
        return num_queued_tasks

    def submit_task(self, callback, *args, **kwargs):
        try:
            future = self.scan._thread_pool.submit(callback, *args, **kwargs)
        except RuntimeError as e:
            raise ScanCancelledError(e)
        with self._future_lock:
            self._futures.add(future)
        return future

    def temp_filename(self):
        return self.temp_dir / self.rand_string(20)

    def empty_temp_dir(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

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
            try:
                return getattr(misc, attr)
            except AttributeError:
                return getattr(self.dns, attr)
