import os
import time
import logging

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
