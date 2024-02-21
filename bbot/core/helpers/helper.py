import os
import logging
from pathlib import Path

from . import misc
from .dns import DNSHelper
from .web import WebHelper
from .diff import HttpCompare
from .cloud import CloudHelper
from .wordcloud import WordCloud
from .interactsh import Interactsh
from ...scanner.target import Target
from ...modules.base import BaseModule
from .depsinstaller import DepsInstaller


log = logging.getLogger("bbot.core.helpers")


class ConfigAwareHelper:
    """
    Centralized helper class that provides unified access to various helper functions.

    This class serves as a convenient interface for accessing helper methods across different files.
    It is designed to be configuration-aware, allowing helper functions to utilize scan-specific
    configurations like rate-limits. The class leverages Python's `__getattribute__` magic method
    to provide seamless access to helper functions across various namespaces.

    Attributes:
        config (dict): Configuration settings for the BBOT scan instance.
        _scan (Scan): A BBOT scan instance.
        bbot_home (Path): Home directory for BBOT.
        cache_dir (Path): Directory for storing cache files.
        temp_dir (Path): Directory for storing temporary files.
        tools_dir (Path): Directory for storing tools, e.g. compiled binaries.
        lib_dir (Path): Directory for storing libraries.
        scans_dir (Path): Directory for storing scan results.
        wordlist_dir (Path): Directory for storing wordlists.
        current_dir (Path): The current working directory.
        keep_old_scans (int): The number of old scans to keep.

    Examples:
        >>> helper = ConfigAwareHelper(config)
        >>> ips = helper.dns.resolve("www.evilcorp.com")
    """

    from . import ntlm
    from . import regexes
    from . import validators
    from .files import tempfile, feed_pipe, _feed_pipe, tempfile_tail
    from .cache import cache_get, cache_put, cache_filename, is_cached
    from .command import run, run_live, _spawn_proc, _prepare_command_kwargs

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

        self.dns = DNSHelper(self)
        self.web = WebHelper(self)
        self.depsinstaller = DepsInstaller(self)
        self.word_cloud = WordCloud(self)
        self.dummy_modules = {}

        # cloud helpers
        self.cloud = CloudHelper(self)

    def interactsh(self, *args, **kwargs):
        return Interactsh(self, *args, **kwargs)

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

    def make_target(self, *events):
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
        Do not be afraid, the angel said.

        Overrides Python's built-in __getattribute__ to provide convenient access to helper methods.

        This method first attempts to find an attribute within this class itself. If unsuccessful,
        it then looks in the 'misc', 'dns', and 'web' helper modules, in that order. If the attribute
        is still not found, an AttributeError is raised.

        Args:
            attr (str): The attribute name to look for.

        Returns:
            Any: The attribute value, if found.

        Raises:
            AttributeError: If the attribute is not found in any of the specified places.
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
                        try:
                            # then try validators
                            return getattr(self.validators, attr)
                        except AttributeError:
                            # then die
                            raise AttributeError(f'Helper has no attribute "{attr}"')


class DummyModule(BaseModule):
    _priority = 4

    def __init__(self, *args, **kwargs):
        self._name = kwargs.pop("name")
        self._type = kwargs.pop("_type")
        super().__init__(*args, **kwargs)
