import atexit
import shutil
import logging
from pathlib import Path
from threading import Lock
from tabulate import tabulate

from . import misc
from .dns import DNSHelper
from .diff import HttpCompare
from .wordcloud import WordCloud
from .threadpool import as_completed
from ...modules.base import BaseModule
from .depsinstaller import DepsInstaller
from .interactsh import Interactsh

log = logging.getLogger("bbot.core.helpers")


class ConfigAwareHelper:
    from .web import wordlist, request, download, api_page_iter, curl
    from .command import run, run_live, tempfile, feed_pipe, _feed_pipe
    from .cache import cache_get, cache_put, cache_filename, is_cached, CacheDict
    from . import ntlm
    from . import regexes
    from . import validators

    def __init__(self, config, scan=None):
        self.config = config
        self._scan = scan
        self.bbot_home = Path(self.config.get("home", "~/.bbot")).expanduser().resolve()
        self.cache_dir = self.bbot_home / "cache"
        self.temp_dir = self.bbot_home / "temp"
        self.tools_dir = self.bbot_home / "tools"
        self.lib_dir = self.bbot_home / "lib"
        self.scans_dir = self.bbot_home / "scans"
        self.current_dir = Path.cwd()
        self.keep_old_scans = self.config.get("keep_scans", 20)
        self.mkdir(self.cache_dir)
        self.mkdir(self.temp_dir)
        self.mkdir(self.tools_dir)
        self.mkdir(self.lib_dir)
        atexit.register(self.empty_temp_dir)
        # holds requests CachedSession() objects for duration of scan
        self.cache_sessions = dict()
        self._futures = set()
        self._future_lock = Lock()

        self.dns = DNSHelper(self)
        self.depsinstaller = DepsInstaller(self)
        self.word_cloud = WordCloud(self)
        self.dummy_modules = {}

    def interactsh(self):
        return Interactsh(self)

    def make_table(self, *args, **kwargs):
        defaults = {
            "tablefmt": "github",
            "disable_numparse": True,
        }
        for k, v in defaults.items():
            if k not in kwargs:
                kwargs[k] = v
        return tabulate(*args, **kwargs)

    def http_compare(self, url, allow_redirects=False):

        return HttpCompare(url, self, allow_redirects=allow_redirects)

    def temp_filename(self):
        """
        temp_filename() --> Path("/home/user/.bbot/temp/pgxml13bov87oqrvjz7a")
        """
        return self.temp_dir / self.rand_string(20)

    def empty_temp_dir(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def clean_old_scans(self):
        _filter = lambda x: x.is_dir() and self.regexes.scan_name_regex.match(x.name)
        self.clean_old(self.scans_dir, keep=self.keep_old_scans, filter=_filter)

    @property
    def scan(self):
        if self._scan is None:
            from bbot.scanner import Scanner

            self._scan = Scanner()
        return self._scan

    @staticmethod
    def as_completed(*args, **kwargs):
        return as_completed(*args, **kwargs)

    def _make_dummy_module(self, name, _type):
        """
        Construct a dummy module, for attachment to events
        """
        try:
            return self.dummy_modules[name]
        except KeyError:
            dummy = DummyModule(scan=self.scan, name=name, _type=_type)
            self.dummy_modules[name] = dummy
            return dummy

    def __getattribute__(self, attr):
        """
        Allow static functions from sub-helpers to be accessed from the main class
        """
        try:
            # first try self
            return super().__getattribute__(attr)
        except AttributeError:
            try:
                # then try misc
                return getattr(misc, attr)
            except AttributeError:
                try:
                    # then try dns
                    return getattr(self.dns, attr)
                except AttributeError:
                    # then die
                    raise AttributeError(f'Helper has no attribute "{attr}"')


class DummyModule(BaseModule):
    def __init__(self, *args, **kwargs):
        self._name = kwargs.pop("name")
        self._type = kwargs.pop("_type")
        super().__init__(*args, **kwargs)
