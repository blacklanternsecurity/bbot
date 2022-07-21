import os
import time
import logging
import threading
from contextlib import suppress
from collections import OrderedDict

from .misc import sha1

log = logging.getLogger("bbot.core.helpers.cache")


def cache_get(self, key, text=True, cache_hrs=24 * 7):
    """
    Get an item from the cache. Default expiration is 1 week.
    Returns None if item is not in cache
    """
    filename = self.cache_filename(key)
    if filename.is_file():
        valid = self.is_cached(key, cache_hrs)
        if valid:
            open_kwargs = {}
            if text:
                open_kwargs.update({"mode": "r", "encoding": "utf-8", "errors": "ignore"})
            else:
                open_kwargs["mode"] = "rb"
            log.debug(f'Using cached content for "{key}"')
            return open(filename, **open_kwargs).read()
        else:
            log.debug(f'Cached content for "{key}" is older than {cache_hrs:,} hours')


def cache_put(self, key, content):
    """
    Put an item in the cache.
    """
    filename = self.cache_filename(key)
    if type(content) == bytes:
        open_kwargs = {"mode": "wb"}
    else:
        open_kwargs = {"mode": "w", "encoding": "utf-8"}
        content = str(content)
    with open(filename, **open_kwargs) as f:
        f.write(content)


def is_cached(self, key, cache_hrs=24 * 7):
    filename = self.cache_filename(key)
    if filename.is_file():
        (m, i, d, n, u, g, sz, atime, mtime, ctime) = os.stat(filename)
        return mtime > time.time() - cache_hrs * 3600
    return False


def cache_filename(self, key):
    return self.cache_dir / sha1(key).hexdigest()


_sentinel = object()


class CacheDict:
    """
    Dictionary to store cached values, with a maximum size limit
    """

    def __init__(self, max_size=1000):
        self._cache = OrderedDict()
        self._lock = threading.Lock()
        self._max_size = int(max_size)

    def get(self, name, fallback=_sentinel):
        name_hash = self._hash(name)
        with self._lock:
            try:
                return self._cache[name_hash]
            except KeyError:
                if fallback is not _sentinel:
                    return fallback
                raise
            finally:
                with suppress(KeyError):
                    self._cache.move_to_end(name_hash)
                self._truncate()

    def put(self, name, value):
        name_hash = self._hash(name)
        with self._lock:
            try:
                self._cache[name_hash] = value
            finally:
                with suppress(KeyError):
                    self._cache.move_to_end(name_hash)
                self._truncate()

    def _truncate(self):
        if not self or len(self) <= self._max_size:
            return
        for nh in list(self._cache.keys()):
            try:
                del self._cache[nh]
            except KeyError:
                pass
            if not self or len(self) <= self._max_size:
                break

    def keys(self):
        return self._cache.keys()

    def values(self):
        return self._cache.values()

    def items(self):
        return self._cache.items()

    def _hash(self, v):
        if type(v) == int:
            return v
        return hash(str(v))

    def __contains__(self, item):
        return self._hash(item) in self._cache

    def __iter__(self):
        return iter(self._cache)

    def __getitem__(self, item):
        return self.get(item)

    def __setitem__(self, item, value):
        self.put(item, value)

    def __bool__(self):
        return bool(self._cache)

    def __len__(self):
        return len(self._cache)
