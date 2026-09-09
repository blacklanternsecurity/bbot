"""
Per-scan disk-spill store for HTTP_RESPONSE bodies.

Bodies are the dominant memory tenant in long-running scans (in our
benchmarks, mid-scan body bytes peak at ~640 MB on a wide-and-busy
workload). Holding them in event objects until ``_minimize()`` fires
keeps Python's working set above what the actual processing pipeline
needs.

This store keeps bodies on disk under ``${scan.temp_dir}/bodies/`` and
serves reads from a bounded LRU cache. The cache absorbs the
processing-window working set; reads only touch disk when the working
set exceeds the cache.

Design (locked-in):

  - **Trigger**: every body always spills (never threshold-based).
  - **Storage**: file-per-event, ``${scan.temp_dir}/bodies/{uuid}.body[.zst]``.
  - **Compression**: zstd level 1 (configurable on/off).
  - **Cache**: bounded by total bytes (default 512 MB), keyed by event
    UUID, value is decompressed body bytes.
  - **Eviction**: biggest-first, FIFO tie-break. (Pure LRU is wrong for
    BBOT's pipeline — "least recently used" tends to be the next event
    to be processed, not a candidate for eviction.)
  - **Reads**: synchronous. Cache hit is instant; misses do a small
    blocking read from page cache (typically microseconds).
  - **Writes**: synchronous to OS page cache (a few hundred microseconds
    for a typical body; OS handles actual disk flush async).
  - **Lifecycle**: file + cache entry are deleted when the event's
    ``_minimize()`` fires. Scan-end ``rm_rf`` of ``temp_dir`` mops up
    anything that escaped.
"""

import logging
from pathlib import Path
from typing import Optional

import zstandard as zstd

log = logging.getLogger("bbot.spill")


class BodySpillStore:
    """
    LRU + on-disk store for HTTP response bodies.

    Bodies are always written to disk on insert. The LRU is a working-set
    cache — hits are fast, misses re-read from disk. Eviction is
    biggest-first with FIFO tie-break, which respects BBOT's roughly-FIFO
    pipeline order (the oldest cache entry is typically the next event
    to be processed, so the smaller-newer entries are safer to evict).

    Thread-safety: not thread-safe. Designed for single-event-loop use
    inside a Scanner. Calls cross the event loop boundary only via
    cooperative ``await``, but I/O itself is synchronous (page cache).

    Hit/miss accounting is exposed via ``stats()`` for benchmark and
    operational visibility.
    """

    # Module-internal sentinel for evicted-but-not-deleted entries during
    # iteration. Currently unused — left here for future async-write work.
    _UNSET = object()

    def __init__(
        self,
        base_dir: Path,
        cache_bytes: int = 512 * 1024 * 1024,
        compress: bool = True,
        compress_level: int = 1,
    ):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.cache_bytes = int(cache_bytes)
        self.compress = bool(compress)
        # Compressors are cheap to construct but reusable.
        self._cctx = zstd.ZstdCompressor(level=compress_level) if compress else None
        self._dctx = zstd.ZstdDecompressor() if compress else None

        # Cache value: dict with bytes + insertion sequence (for FIFO tie-break).
        # {uuid: {"body": bytes, "seq": int}}
        self._cache: dict[str, dict] = {}
        self._cache_total_bytes = 0
        self._seq = 0  # monotonic insertion counter

        # Stats
        self._hits = 0
        self._misses = 0
        self._writes = 0
        self._evictions = 0

    # ── Public API ────────────────────────────────────────────────────

    def write(self, event_uuid: str, body: bytes) -> None:
        """
        Spill a body to disk and seed the cache. The body remains
        immediately readable (cache hit) until evicted; thereafter,
        reads pull from disk.

        ``body`` must be ``bytes``. Callers passing ``str`` should
        ``.encode("utf-8", errors="replace")`` first.
        """
        if not isinstance(body, (bytes, bytearray, memoryview)):
            raise TypeError(f"body must be bytes-like, got {type(body).__name__}")
        body_bytes = bytes(body)

        path = self._path_for(event_uuid)
        if self.compress:
            on_disk = self._cctx.compress(body_bytes)
        else:
            on_disk = body_bytes

        # Synchronous write to page cache. Fast (memcpy), the OS does
        # the real disk flush asynchronously.
        path.write_bytes(on_disk)
        self._writes += 1

        self._insert_cache(event_uuid, body_bytes)

    def read(self, event_uuid: str) -> Optional[bytes]:
        """
        Return the body for ``event_uuid``, or ``None`` if neither
        cache nor disk has it.

        Cache hit: instant. Cache miss + file present: small blocking
        disk read (page-cached after first hit).
        """
        entry = self._cache.get(event_uuid)
        if entry is not None:
            self._hits += 1
            return entry["body"]

        # Miss — try disk.
        path = self._path_for(event_uuid)
        if not path.exists():
            self._misses += 1
            return None

        on_disk = path.read_bytes()
        body_bytes = self._dctx.decompress(on_disk) if self.compress else on_disk

        self._misses += 1
        self._insert_cache(event_uuid, body_bytes)
        return body_bytes

    def evict_and_delete(self, event_uuid: str) -> None:
        """
        Drop ``event_uuid`` from the cache and delete the file.

        Called from ``HTTP_RESPONSE._minimize()`` when the event is no
        longer needed by any module.
        """
        entry = self._cache.pop(event_uuid, None)
        if entry is not None:
            self._cache_total_bytes -= len(entry["body"])

        path = self._path_for(event_uuid)
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except Exception as e:  # pragma: no cover — defensive
            log.debug(f"failed to unlink spill file {path}: {e}")

    def stats(self) -> dict:
        """Hit/miss/eviction counters and current cache fill."""
        total = self._hits + self._misses
        hit_rate = (self._hits / total) if total else 0.0
        return {
            "hits": self._hits,
            "misses": self._misses,
            "writes": self._writes,
            "evictions": self._evictions,
            "hit_rate": round(hit_rate, 4),
            "cache_entries": len(self._cache),
            "cache_bytes": self._cache_total_bytes,
            "cache_bytes_limit": self.cache_bytes,
        }

    # ── Internal ──────────────────────────────────────────────────────

    def _path_for(self, event_uuid: str) -> Path:
        suffix = ".body.zst" if self.compress else ".body"
        return self.base_dir / f"{event_uuid}{suffix}"

    def _insert_cache(self, event_uuid: str, body_bytes: bytes) -> None:
        """Insert into cache, evicting biggest-first / oldest-first as needed."""
        body_size = len(body_bytes)

        # Replace existing entry if present (keeps semantics simple if a
        # body is rewritten — currently never happens, but cheap insurance).
        existing = self._cache.pop(event_uuid, None)
        if existing is not None:
            self._cache_total_bytes -= len(existing["body"])

        # If a single body exceeds the entire cache budget, don't try
        # to cache it — disk reads will be the only path.
        if body_size > self.cache_bytes:
            return

        # Evict until there's room.
        while self._cache_total_bytes + body_size > self.cache_bytes and self._cache:
            self._evict_one()

        self._seq += 1
        self._cache[event_uuid] = {"body": body_bytes, "seq": self._seq}
        self._cache_total_bytes += body_size

    def _evict_one(self) -> None:
        """Pick a victim by ``(-size, seq)`` — biggest-first, FIFO tie-break."""
        # Single-pass min: maximize size, minimize seq among ties.
        victim_uuid = None
        victim_size = -1
        victim_seq = float("inf")
        for u, entry in self._cache.items():
            sz = len(entry["body"])
            if sz > victim_size or (sz == victim_size and entry["seq"] < victim_seq):
                victim_uuid = u
                victim_size = sz
                victim_seq = entry["seq"]
        if victim_uuid is None:  # pragma: no cover — empty cache, defensive
            return
        entry = self._cache.pop(victim_uuid)
        self._cache_total_bytes -= len(entry["body"])
        self._evictions += 1
