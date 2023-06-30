import os
import logging
from pathlib import Path
from threading import Lock

from . import misc
from .dns import DNSHelper
from .web import WebHelper
from .diff import HttpCompare
from .wordcloud import WordCloud
from .cloud import CloudProviders
from .interactsh import Interactsh
from ...scanner.target import Target
from ...modules.base import BaseModule
from .depsinstaller import DepsInstaller


log = logging.getLogger("bbot.core.helpers")


class ConfigAwareHelper:
    from . import ntlm
    from . import regexes
    from . import validators
    from .files import tempfile, feed_pipe, _feed_pipe, tempfile_tail
    from .command import run, run_live, _spawn_proc, _prepare_command_kwargs
    from .cache import cache_get, cache_put, cache_filename, is_cached, CacheDict

    def __init__(self, config, scan=None):
        self.config = config
        self._scan = scan
        self.bbot_home = Path(self.config.get("home", "~/.bbot")).expanduser().resolve()
        self.cache_dir = self.bbot_home / "cache"
        self.temp_dir = self.bbot_home / "temp"
        self.tools_dir = self.bbot_home / "tools"
        self.lib_dir = self.bbot_home / "lib"
        self.scans_dir = self.bbot_home / "scans"
        self.wordlist_dir = Path(__file__).parent.parent.parent / "wordlists"
        self.current_dir = Path.cwd()
        self.keep_old_scans = self.config.get("keep_scans", 20)
        self.mkdir(self.cache_dir)
        self.mkdir(self.temp_dir)
        self.mkdir(self.tools_dir)
        self.mkdir(self.lib_dir)
        self._futures = set()
        self._future_lock = Lock()

        self.dns = DNSHelper(self)
        self.web = WebHelper(self)
        self.depsinstaller = DepsInstaller(self)
        self.word_cloud = WordCloud(self)
        self.dummy_modules = {}

        # cloud helpers
        self.cloud = CloudProviders(self)

    def interactsh(self):
        return Interactsh(self)

    def http_compare(self, url, allow_redirects=False, include_cache_buster=True):
        return HttpCompare(url, self, allow_redirects=allow_redirects, include_cache_buster=include_cache_buster)

    def temp_filename(self, extension=None):
        """
        temp_filename() --> Path("/home/user/.bbot/temp/pgxml13bov87oqrvjz7a")
        """
        filename = self.rand_string(20)
        if extension is not None:
            filename = f"{filename}.{extension}"
        return self.temp_dir / filename

    def clean_old_scans(self):
        _filter = lambda x: x.is_dir() and self.regexes.scan_name_regex.match(x.name)
        self.clean_old(self.scans_dir, keep=self.keep_old_scans, filter=_filter)

    def make_target(self, events):
        return Target(self.scan, *events)

    @property
    def scan(self):
        if self._scan is None:
            from bbot.scanner import Scanner

            self._scan = Scanner()
        return self._scan

    @property
    def in_tests(self):
        return os.environ.get("BBOT_TESTING", "") == "True"

    def _make_dummy_module(self, name, _type="scan"):
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
                    try:
                        # then try web
                        return getattr(self.web, attr)
                    except AttributeError:
                        # then die
                        raise AttributeError(f'Helper has no attribute "{attr}"')


class DummyModule(BaseModule):
    _priority = 4

    def __init__(self, *args, **kwargs):
        self._name = kwargs.pop("name")
        self._type = kwargs.pop("_type")
        super().__init__(*args, **kwargs)
