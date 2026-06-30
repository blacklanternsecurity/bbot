import os
import sys
import signal
import ctypes
import ctypes.util
import asyncio
import logging
from pathlib import Path
import multiprocessing as mp
from functools import partial
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

from . import misc
from .asn import ASNHelper
from .dns import DNSHelper
from .web import WebHelper
from .diff import HttpCompare
from .regex import RegexHelper
from .wordcloud import WordCloud
from .interactsh import Interactsh
from .yara_helper import YaraHelper
from .simhash import SimHashHelper
from .depsinstaller import DepsInstaller
from .async_helpers import get_event_loop

from bbot.scanner.target import BaseTarget

log = logging.getLogger("bbot.core.helpers")

_PR_SET_PDEATHSIG = 1


def _pool_worker_init():
    """Set PR_SET_PDEATHSIG so pool workers die when the parent process dies.

    Prevents zombie worker accumulation after OOM kills, SIGKILL, etc.
    Uses SIGKILL because ProcessPoolExecutor's `except BaseException` catches
    SIGTERM's SystemExit, keeping workers alive until the broken pipe surfaces.

    prctl is Linux-specific, so this is a no-op elsewhere (the symbol is absent
    on other platforms and would otherwise raise, breaking the whole pool).
    """
    if not sys.platform.startswith("linux"):
        return
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0)


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

    def __init__(self, preset):
        self.preset = preset
        self.bbot_home = self.preset.bbot_home
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

        self._loop = None

        # multiprocessing process pool
        start_method = mp.get_start_method()
        if start_method != "spawn":
            self.warning(f"Multiprocessing spawn method is set to {start_method}.")
        self.process_pool = self._create_process_pool()
        self._pool_reset_lock = asyncio.Lock()

        self._cloud = None
        self._blasthttp_client = None

        self.re = RegexHelper(self)
        self.yara = YaraHelper(self)
        self.simhash = SimHashHelper()
        self._dns = None
        self._web = None
        self._asn = None
        self._cloudcheck = None
        self._asn = None
        self.config_aware_validators = self.validators.Validators(self)
        self.depsinstaller = DepsInstaller(self)
        self.word_cloud = WordCloud(self)
        self.dummy_modules = {}

    @property
    def dns(self):
        if self._dns is None:
            self._dns = DNSHelper(self)
        return self._dns

    @property
    def web(self):
        if self._web is None:
            self._web = WebHelper(self)
        return self._web

    @property
    def asn(self):
        if self._asn is None:
            self._asn = ASNHelper(self)
        return self._asn

    @property
    def blasthttp(self):
        if self._blasthttp_client is None:
            import blasthttp as _blasthttp

            self._blasthttp_client = _blasthttp.BlastHTTP()
            rate_limit = self.web_config.get("http_rate_limit", 0)
            if rate_limit:
                self._blasthttp_client.set_rate_limit(rate_limit)
        return self._blasthttp_client

    @property
    def cloudcheck(self):
        if self._cloudcheck is None:
            from cloudcheck import CloudCheck

            ssl_verify = self.web_config.get("ssl_verify_infrastructure", True)
            self._cloudcheck = CloudCheck(verify_ssl=ssl_verify)
        return self._cloudcheck

    def bloom_filter(self, size):
        from .bloom import BloomFilter

        return BloomFilter(size)

    def interactsh(self, *args, **kwargs):
        return Interactsh(self, *args, **kwargs)

    def http_compare(
        self,
        url,
        allow_redirects=False,
        include_cache_buster=True,
        headers=None,
        cookies=None,
        method="GET",
        data=None,
        json=None,
        timeout=10,
        on_baseline_ready=None,
    ):
        return HttpCompare(
            url,
            self,
            allow_redirects=allow_redirects,
            include_cache_buster=include_cache_buster,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            method=method,
            data=data,
            json=json,
            on_baseline_ready=on_baseline_ready,
        )

    def temp_filename(self, extension=None):
        """
        temp_filename() --> Path("/home/user/.bbot/temp/pgxml13bov87oqrvjz7a")
        """
        filename = self.rand_string(20)
        if extension is not None:
            filename = f"{filename}.{extension}"
        return self.temp_dir / filename

    def clean_old_scans(self):
        def _filter(x):
            return x.is_dir() and self.regexes.scan_name_regex.match(x.name)

        self.clean_old(self.scans_dir, keep=self.keep_old_scans, filter=_filter)

    def make_target(self, *targets, **kwargs):
        return BaseTarget(*targets, **kwargs)

    @property
    def config(self):
        return self.preset.config

    @property
    def web_config(self):
        return self.preset.web_config

    @property
    def scan(self):
        return self.preset.scan

    @property
    def loop(self):
        """
        Get the current event loop
        """
        if self._loop is None:
            self._loop = get_event_loop()
            # only current caller is wafw00f (sync requests library)
            self._io_executor = ThreadPoolExecutor(max_workers=max(8, (os.cpu_count() or 1) + 4))
            self._cpu_executor = ThreadPoolExecutor(max_workers=max(8, os.cpu_count() or 4))
            self._loop.set_default_executor(self._io_executor)
        return self._loop

    @staticmethod
    def _create_process_pool():
        # we spawn 1 fewer processes than cores
        # this helps to avoid locking up the system or competing with the main python process for cpu time
        num_processes = max(1, mp.cpu_count() - 1)
        pool_kwargs = {"max_workers": num_processes, "initializer": _pool_worker_init}
        # max_tasks_per_child replaces workers after N tasks, preventing memory leaks
        # and reducing the chance of a degraded worker process causing hangs
        if sys.version_info >= (3, 11):
            pool_kwargs["max_tasks_per_child"] = 25
        return ProcessPoolExecutor(**pool_kwargs)

    def run_in_executor_io(self, callback, *args, **kwargs):
        """
        Run a synchronous task in the event loop's default thread pool executor

        Examples:
            Execute callback:
            >>> result = await self.helpers.run_in_executor_io(callback_fn, arg1, arg2)
        """
        callback = partial(callback, **kwargs)
        return self.loop.run_in_executor(self._io_executor, callback, *args)

    def run_in_executor_cpu(self, callback, *args, **kwargs):
        """
        Run short CPU-bound work that releases the GIL in a dedicated thread pool,
        separate from I/O so it never queues behind long-running network calls.

        Examples:
            Execute callback:
            >>> result = await self.helpers.run_in_executor_cpu(callback_fn, arg1, arg2)
        """
        callback = partial(callback, **kwargs)
        return self.loop.run_in_executor(self._cpu_executor, callback, *args)

    async def run_in_executor_mp(self, callback, *args, **kwargs):
        """
        Same as run_in_executor_io() except with a process pool executor.
        Use only in cases where callback is CPU-bound.

        Includes a timeout (default 300s) to prevent indefinite hangs if a child process dies or the pool enters a broken state.
        On timeout, the entire pool is terminated and replaced so that stuck workers cannot accumulate and starve the scan.

        Pass ``_timeout=seconds`` to override the default timeout.

        Examples:
            Execute callback:
            >>> result = await self.helpers.run_in_executor_mp(callback_fn, arg1, arg2)
        """
        timeout = kwargs.pop("_timeout", 300)
        callback = partial(callback, **kwargs)
        future = self.loop.run_in_executor(self.process_pool, callback, *args)
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            log.warning(f"Process pool task timed out after {timeout}s, killing stuck workers and replacing pool")
            await self._reset_process_pool()
            raise

    async def _reset_process_pool(self):
        """Terminate all workers in the current process pool and replace it.

        This is the nuclear option — every in-flight task on the old pool will fail with BrokenProcessPool.
        We accept that trade-off because a timeout means something is genuinely broken, and leaving the stuck worker alive would permanently consume a pool slot.

        # TODO: Python 3.14 adds ProcessPoolExecutor.terminate_workers()
        # and kill_workers() (https://github.com/python/cpython/pull/130849).
        # Once we drop 3.13 support we can replace the _processes access
        # with those official methods.
        """
        async with self._pool_reset_lock:
            old_pool = self.process_pool
            self.process_pool = self._create_process_pool()
            # snapshot workers before shutdown (shutdown sets _processes = None)
            workers = list((old_pool._processes or {}).values())
            # terminate workers before shutdown so stuck ones don't block
            for proc in workers:
                if proc.is_alive():
                    proc.terminate()
            old_pool.shutdown(wait=False, cancel_futures=True)
            # escalate to SIGKILL for anything that ignored SIGTERM
            for proc in workers:
                if proc.is_alive():
                    proc.kill()

    @property
    def in_tests(self):
        return os.environ.get("BBOT_TESTING", "") == "True"

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
