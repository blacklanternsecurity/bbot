"""
Tests for HTTP_RESPONSE body disk-spill (``bbot.core.event.spill``).

Two layers:
  - ``TestBodySpillStore``: direct unit tests of the LRU + disk store.
  - ``TestHTTPResponseSpill``: integration tests asserting that
    HTTP_RESPONSE events route bodies through the spill store when one
    is attached to the scan, and fall back to in-memory data when not.
  - ``TestBaselineSnapshot``: unit tests of the HttpCompare baseline
    snapshot that also spills its body through the store.
"""

import gc

import pytest

from bbot.core.event.spill import BodySpillStore
from bbot.core.helpers.diff import _BaselineSnapshot

from ..bbot_fixtures import *  # noqa: F401, F403


class _FakeResponse:
    """Minimal stand-in for a blasthttp Response for snapshot tests."""

    def __init__(self, body_bytes=b"", text="", status_code=200, headers=None):
        self.body_bytes = body_bytes
        self.text = text
        self.status_code = status_code
        self.headers = {} if headers is None else headers


# ── BodySpillStore unit tests ─────────────────────────────────────────


class TestBodySpillStore:
    def test_roundtrip_compressed(self, tmp_path):
        store = BodySpillStore(tmp_path, cache_bytes=4096, compress=True)
        # Every byte value plus some recognizable binary magic. If a UTF-8
        # round-trip ever sneaks back in, this body would be corrupted.
        raw = bytes(range(256)) + b"PK\x03\x04hello"
        store.write("uuid-1", raw)
        assert store.read("uuid-1") == raw

    def test_roundtrip_uncompressed(self, tmp_path):
        store = BodySpillStore(tmp_path, cache_bytes=4096, compress=False)
        raw = b"hello world\x00\xff"
        store.write("uuid-1", raw)
        assert store.read("uuid-1") == raw

    def test_cache_hit_does_not_touch_disk(self, tmp_path):
        # After write, body is in cache. Delete the file. Read should still
        # succeed because the cache holds the body.
        store = BodySpillStore(tmp_path, cache_bytes=4096)
        store.write("uuid-1", b"hello")
        for f in tmp_path.iterdir():
            f.unlink()
        assert store.read("uuid-1") == b"hello"

    def test_cache_miss_loads_from_disk(self, tmp_path):
        # Force eviction by inserting another body that pushes the first out.
        store = BodySpillStore(tmp_path, cache_bytes=200, compress=False)
        store.write("a", b"X" * 150)
        store.write("b", b"Y" * 150)  # would total 300 — must evict 'a'
        assert "a" not in store._cache
        # 'a' is still on disk; reading should miss the cache and fetch it.
        prior_misses = store.stats()["misses"]
        assert store.read("a") == b"X" * 150
        assert store.stats()["misses"] == prior_misses + 1

    def test_eviction_biggest_first(self, tmp_path):
        """
        Cache budget of 300; insert small (50), medium (100), then big (200).
        big triggers eviction. Among current cache contents (small=50,
        medium=100), biggest-first picks medium.
        """
        store = BodySpillStore(tmp_path, cache_bytes=300, compress=False)
        store.write("small", b"X" * 50)
        store.write("medium", b"Y" * 100)
        store.write("big", b"Z" * 200)
        assert "small" in store._cache
        assert "big" in store._cache
        assert "medium" not in store._cache
        assert store.stats()["evictions"] == 1

    def test_eviction_fifo_tiebreak(self, tmp_path):
        """
        Two equal-size entries. Inserting a third forces eviction; the
        older one (smaller seq) goes first.
        """
        store = BodySpillStore(tmp_path, cache_bytes=200, compress=False)
        store.write("first", b"A" * 100)
        store.write("second", b"B" * 100)  # cache full at 200
        store.write("new", b"C" * 50)  # forces eviction of 'first'
        assert "first" not in store._cache
        assert "second" in store._cache
        assert "new" in store._cache

    def test_oversized_body_skips_cache(self, tmp_path):
        """A body bigger than the entire cache budget is written to disk
        but never enters the cache (would force-evict everything else
        for nothing)."""
        store = BodySpillStore(tmp_path, cache_bytes=100, compress=False)
        store.write("huge", b"X" * 500)
        assert "huge" not in store._cache
        # Still readable from disk
        assert store.read("huge") == b"X" * 500

    def test_evict_and_delete_removes_file_and_cache(self, tmp_path):
        store = BodySpillStore(tmp_path, cache_bytes=4096)
        store.write("uuid-1", b"hello")
        assert any(tmp_path.iterdir())
        store.evict_and_delete("uuid-1")
        assert "uuid-1" not in store._cache
        assert not list(tmp_path.iterdir())
        # Subsequent reads return None
        assert store.read("uuid-1") is None

    def test_stats(self, tmp_path):
        store = BodySpillStore(tmp_path, cache_bytes=4096)
        store.write("a", b"hello")
        store.read("a")  # hit
        store.read("nonexistent")  # miss + nothing on disk
        s = store.stats()
        assert s["hits"] == 1
        assert s["misses"] == 1
        assert s["writes"] == 1
        assert s["hit_rate"] == 0.5

    def test_empty_body_not_written(self, tmp_path):
        # Caller is expected to skip empty bodies; the store doesn't enforce
        # but should at least roundtrip cleanly.
        store = BodySpillStore(tmp_path, cache_bytes=4096)
        store.write("empty", b"")
        # zstd-compressed empty bytes is still a small frame; we should
        # be able to round-trip to b"".
        assert store.read("empty") == b""

    def test_rejects_non_bytes(self, tmp_path):
        store = BodySpillStore(tmp_path, cache_bytes=4096)
        with pytest.raises(TypeError):
            store.write("uuid-1", "string-not-bytes")  # type: ignore[arg-type]


# ── HTTP_RESPONSE event integration tests ────────────────────────────


@pytest.fixture
def fake_response_data():
    """Minimal valid HTTP_RESPONSE data dict."""
    return {
        "url": "http://example.com:80/",
        "input": "http://example.com:80/",
        "method": "GET",
        "path": "/",
        "host": "example.com",
        "status_code": 200,
        "title": "Example",
        "raw_header": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
        "header": {"content_type": "text/html"},
        "content_type": "text/html",
        "content_length": 23,
        "body": "<html><body>hi</body></html>",
        "location": "",
        "hash": {
            "body_md5": "x" * 32,
            "body_mmh3": "0",
            "body_sha256": "x" * 64,
            "header_md5": "x" * 32,
            "header_mmh3": "0",
            "header_sha256": "x" * 64,
        },
    }


class TestHTTPResponseSpill:
    @pytest.mark.asyncio
    async def test_body_routed_through_spill_store(self, bbot_scanner, fake_response_data):
        """When a scan has a body_spill_store, body is removed from _data
        and accessed via event.body which reads from the store."""
        scan = bbot_scanner("http://example.com")
        await scan._prep()
        assert scan.body_spill_store is not None, "body_spill_store should be created in _prep"

        event = scan.make_event(fake_response_data, "HTTP_RESPONSE", parent=scan.root_event)
        # body should NOT be in _data (it's been spilled)
        assert "body" not in event._data
        # but event.body should still return the original body
        assert event.body == "<html><body>hi</body></html>"
        # And the spill store has it
        assert scan.body_spill_store.stats()["writes"] >= 1

    @pytest.mark.asyncio
    async def test_minimize_evicts_and_deletes(self, bbot_scanner, fake_response_data):
        """When _minimize() drops _module_consumers to 0, the body file
        and cache entry should be removed."""
        scan = bbot_scanner("http://example.com")
        await scan._prep()

        event = scan.make_event(fake_response_data, "HTTP_RESPONSE", parent=scan.root_event)
        # Force a normal lifecycle: bump consumers up then drain to 0
        event._module_consumers = 1
        event._minimize()  # drops to 0 → triggers eviction
        # After minimize, body should be gone
        assert event.body == ""
        # File should be deleted
        bodies_dir = scan.temp_dir / "bodies"
        assert not list(bodies_dir.iterdir()) or all(str(event._uuid) not in p.name for p in bodies_dir.iterdir())

    @pytest.mark.asyncio
    async def test_disabled_falls_back_to_in_memory(self, bbot_scanner, fake_response_data):
        """When body_spill is disabled in config, body stays in _data and
        event.body falls through to it."""
        scan = bbot_scanner(
            "http://example.com",
            config={"web": {"body_spill": {"enabled": False}}},
        )
        await scan._prep()
        assert scan.body_spill_store is None, "store should not be created when disabled"

        event = scan.make_event(fake_response_data, "HTTP_RESPONSE", parent=scan.root_event)
        # body remains in _data
        assert event._data.get("body") == "<html><body>hi</body></html>"
        # event.body still works
        assert event.body == "<html><body>hi</body></html>"

    @pytest.mark.asyncio
    async def test_raw_response_uses_spilled_body(self, bbot_scanner, fake_response_data):
        """The raw_response property should reconstruct the body from
        the spill store, not from _data."""
        scan = bbot_scanner("http://example.com")
        await scan._prep()

        event = scan.make_event(fake_response_data, "HTTP_RESPONSE", parent=scan.root_event)
        raw = event.raw_response
        assert "<html><body>hi</body></html>" in raw
        assert "HTTP/1.1 200 OK" in raw


# ── _BaselineSnapshot unit tests ──────────────────────────────────────


class TestBaselineSnapshot:
    def test_roundtrip_via_spill_store(self, tmp_path):
        """text/content are served from the spill store, not pinned on the snapshot."""
        store = BodySpillStore(tmp_path, cache_bytes=4096)
        body = "<html>ünïcödé body</html>".encode("utf-8")
        snap = _BaselineSnapshot(_FakeResponse(body_bytes=body), spill_store=store)
        assert snap.content == body
        assert snap.text == body.decode("utf-8")
        assert snap._text is None  # body is not held on the Python object

    def test_no_spill_store_falls_back_to_memory(self, tmp_path):
        """Without a store, text/content come from the in-memory text."""
        snap = _BaselineSnapshot(_FakeResponse(text="hello"), spill_store=None)
        assert snap.text == "hello"
        assert snap.content == b"hello"
        assert not any(tmp_path.iterdir())

    def test_del_reclaims_spilled_body(self, tmp_path):
        """Garbage-collecting the snapshot deletes its spill file and cache entry."""
        store = BodySpillStore(tmp_path, cache_bytes=4096)
        snap = _BaselineSnapshot(_FakeResponse(body_bytes=b"X" * 256), spill_store=store)
        assert any(tmp_path.iterdir())
        assert store.stats()["cache_entries"] == 1

        del snap
        gc.collect()
        assert not list(tmp_path.iterdir())
        assert store.stats()["cache_entries"] == 0

    def test_cleanup_is_idempotent(self, tmp_path):
        """Calling _cleanup twice (e.g. explicit + __del__) is safe."""
        store = BodySpillStore(tmp_path, cache_bytes=4096)
        snap = _BaselineSnapshot(_FakeResponse(body_bytes=b"data"), spill_store=store)
        snap._cleanup()
        snap._cleanup()
        assert not list(tmp_path.iterdir())
