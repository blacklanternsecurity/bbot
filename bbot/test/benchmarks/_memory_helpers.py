"""
Shared memory measurement helpers for scan benchmarks.

Each helper is independent — pick the ones you need. Designed to be used
from subprocess scan scripts (so tracemalloc + psutil polling are not
contaminated by pytest's own allocations).

Three measurement angles, each answering a different question:

  - ``RSSSampler``: actual OS-level RAM (catches Rust / lxml / yara that
    tracemalloc misses). Headline metrics: peak, end, retention (median
    over the last 25% of samples — the metric most sensitive to
    "stuck for the rest of the scan" pathology).

  - ``event_census``: who is alive right now, grouped by event type, with
    HTTP_RESPONSE body bytes broken out separately. Answers
    "where is the memory going?".

  - ``lineage_census``: walk every live event's parent chain back to the
    seed and bucket pinned events by seed. Answers "is the chain
    holding things alive?".
"""

import gc
import json
import threading
import time
import weakref

import psutil


class RSSSampler:
    """
    Background thread that polls process RSS at a fixed interval.

    Usage::

        sampler = RSSSampler(interval_s=0.2)
        sampler.start()
        # ... do work ...
        sampler.stop()
        m = sampler.metrics()  # peak_rss_mb, end_rss_mb, retention_rss_mb
    """

    def __init__(self, interval_s=0.2):
        self.interval_s = interval_s
        self.samples = []  # list of (t, rss_mb)
        self._stop = threading.Event()
        self._thread = None
        self._proc = psutil.Process()

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        t0 = time.monotonic()
        while not self._stop.is_set():
            rss_mb = self._proc.memory_info().rss / 1024 / 1024
            self.samples.append((time.monotonic() - t0, rss_mb))
            self._stop.wait(self.interval_s)

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    def metrics(self):
        if not self.samples:
            return {
                "peak_rss_mb": 0.0,
                "end_rss_mb": 0.0,
                "retention_rss_mb": 0.0,
                "samples": 0,
                "duration_s": 0.0,
            }
        rss_values = [r for _, r in self.samples]
        peak_rss_mb = max(rss_values)
        end_rss_mb = rss_values[-1]
        # median over the last 25% of samples — robust to a single
        # transient spike at the tail and sensitive to baseline drift.
        last_quartile_start = max(1, int(len(rss_values) * 0.75))
        last_quartile = sorted(rss_values[last_quartile_start:])
        retention_rss_mb = last_quartile[len(last_quartile) // 2]
        duration_s = self.samples[-1][0]
        return {
            "peak_rss_mb": round(peak_rss_mb, 2),
            "end_rss_mb": round(end_rss_mb, 2),
            "retention_rss_mb": round(retention_rss_mb, 2),
            "samples": len(self.samples),
            "duration_s": round(duration_s, 2),
        }


class LiveEventTracker:
    """
    Mid-scan event census via weakref, without scanning the full Python
    object graph.

    ``event_census()`` calls ``gc.get_objects()`` and walks every Python
    object — fine at scan-end (one-shot), too expensive to call every
    few hundred events. ``LiveEventTracker`` patches
    ``BaseEvent.__init__`` to register newcomers into a ``WeakSet``, so
    ``census()`` is O(live events) instead of O(every Python object).

    Usage::

        tracker = LiveEventTracker()
        tracker.install()
        # ... run scan, calling tracker.census() periodically ...
        tracker.uninstall()  # optional; not needed if the process exits
    """

    def __init__(self):
        self._events = weakref.WeakSet()
        self._original_init = None
        self._patched = False

    def install(self):
        if self._patched:
            return
        from bbot.core.event.base import BaseEvent

        # Seed with any events that already exist (e.g. SCAN root_event
        # created before install).
        for obj in gc.get_objects():
            if isinstance(obj, BaseEvent):
                self._events.add(obj)

        original_init = BaseEvent.__init__
        events_ref = self._events

        def patched_init(self_evt, *a, **kw):
            original_init(self_evt, *a, **kw)
            try:
                events_ref.add(self_evt)
            except TypeError:
                # Not weakref-able for some reason; skip silently.
                pass

        self._original_init = original_init
        BaseEvent.__init__ = patched_init
        self._patched = True

    def uninstall(self):
        if not self._patched:
            return
        from bbot.core.event.base import BaseEvent

        BaseEvent.__init__ = self._original_init
        self._patched = False

    def census(self):
        """O(live events) census. Same shape as ``event_census()``."""
        by_type = {}
        body_bytes = 0
        body_count = 0
        for obj in self._events:
            by_type[obj.type] = by_type.get(obj.type, 0) + 1
            if obj.type == "HTTP_RESPONSE":
                data = getattr(obj, "data", None)
                body = data.get("body") if isinstance(data, dict) else None
                if body:
                    body_count += 1
                    body_bytes += len(body)
        return {
            "live_events": sum(by_type.values()),
            "by_type": by_type,
            "http_response_body_mb": round(body_bytes / 1024 / 1024, 2),
            "http_response_with_body": body_count,
        }


def event_census():
    """
    Walk live BaseEvent instances and classify by type + HTTP_RESPONSE body bytes.

    Returns a dict::

        {
          "live_events": int,
          "by_type": {"DNS_NAME": int, "HTTP_RESPONSE": int, ...},
          "http_response_body_mb": float,
          "http_response_with_body": int,
        }
    """
    from bbot.core.event.base import BaseEvent

    gc.collect()
    by_type = {}
    body_bytes = 0
    body_count = 0

    for obj in gc.get_objects():
        if not isinstance(obj, BaseEvent):
            continue
        by_type[obj.type] = by_type.get(obj.type, 0) + 1
        if obj.type == "HTTP_RESPONSE":
            data = getattr(obj, "data", None)
            body = data.get("body") if isinstance(data, dict) else None
            if body:
                body_count += 1
                body_bytes += len(body)

    return {
        "live_events": sum(by_type.values()),
        "by_type": by_type,
        "http_response_body_mb": round(body_bytes / 1024 / 1024, 2),
        "http_response_with_body": body_count,
    }


def lineage_census(top_n=20):
    """
    Walk every live BaseEvent's parent chain back to the seed and bucket
    pinned events by seed.

    A long-lived seed pinning hundreds of events is the signature of the
    chain-retention pathology — this is the metric that proves a fix.

    Returns::

        {
          "seeds": [{"seed": str, "pinned_events": int,
                     "max_chain_depth": int,
                     "types_pinned": {type: count, ...}}, ...],  # top N
          "total_pinned_events": int,
          "max_chain_depth": int,
          "live_events_walked": int,
        }
    """
    from bbot.core.event.base import BaseEvent

    gc.collect()
    seeds = {}
    max_chain_depth = 0
    walked = 0

    for obj in gc.get_objects():
        if not isinstance(obj, BaseEvent):
            continue
        walked += 1
        depth = 0
        node = obj
        # Walk up via .parent. Root events are self-parented (node.parent is node).
        while node is not None and node is not getattr(node, "parent", None):
            depth += 1
            parent = getattr(node, "parent", None)
            if parent is None or parent is node:
                break
            node = parent
        if node is None:
            continue
        max_chain_depth = max(max_chain_depth, depth)
        seed_data = getattr(node, "data", None)
        seed_data_str = str(seed_data)[:80] if seed_data is not None else "<no-data>"
        seed_key = f"{node.type}:{seed_data_str}"
        s = seeds.setdefault(
            seed_key,
            {"pinned_events": 0, "max_chain_depth": 0, "types_pinned": {}},
        )
        s["pinned_events"] += 1
        s["max_chain_depth"] = max(s["max_chain_depth"], depth)
        s["types_pinned"][obj.type] = s["types_pinned"].get(obj.type, 0) + 1

    sorted_seeds = sorted(
        ({"seed": k, **v} for k, v in seeds.items()),
        key=lambda x: -x["pinned_events"],
    )
    return {
        "seeds": sorted_seeds[:top_n],
        "total_pinned_events": sum(v["pinned_events"] for v in seeds.values()),
        "max_chain_depth": max_chain_depth,
        "live_events_walked": walked,
    }


def queue_residence(scan, tracker):
    """
    Classify live events by where they currently live in the scan
    pipeline.

    Two angles, since they answer different questions:

      - Per-module queue depth (``by_queue``): which module is the
        current bottleneck — events are piling up where queue depth is
        large.
      - In-pipeline vs. chain-only (``in_pipeline`` / ``chain_only``):
        of the live events, how many are still being processed by some
        module (``event._module_consumers > 0``) vs. how many are
        held alive *only* by the parent chain. The chain_only count is
        the chain-retention pathology made directly visible.

    Returns::

        {
          "in_pipeline": int,    # _module_consumers > 0
          "chain_only": int,     # _module_consumers == 0
          "queue_total": int,    # sum of all module queue depths
          "by_queue": {module_name: {"incoming": int, "outgoing": int}, ...},
        }
    """
    by_queue = {}
    for module in scan.modules.values():
        m_name = getattr(module, "name", str(module))
        in_q = getattr(module, "_incoming_event_queue", None)
        out_q = getattr(module, "_outgoing_event_queue", None)
        in_count = 0
        out_count = 0
        # asyncio.Queue / ShuffleQueue both expose the underlying ``_queue`` deque.
        if in_q and in_q is not False and hasattr(in_q, "_queue"):
            in_count = len(in_q._queue)
        if out_q and hasattr(out_q, "_queue"):
            out_count = len(out_q._queue)
        if in_count or out_count:
            by_queue[m_name] = {"incoming": in_count, "outgoing": out_count}

    in_pipeline = 0
    chain_only = 0
    # Iterate the WeakSet directly — O(live events).
    for ev in tracker._events:
        if getattr(ev, "_module_consumers", 0) > 0:
            in_pipeline += 1
        else:
            chain_only += 1

    return {
        "in_pipeline": in_pipeline,
        "chain_only": chain_only,
        "queue_total": sum(d["incoming"] + d["outgoing"] for d in by_queue.values()),
        "by_queue": by_queue,
    }


def emit_metrics_json(**metrics):
    """
    Print a single ``METRICS_JSON:`` line that ``test_scan_memory.py`` parses.

    Backward-compat: also prints the legacy ``PEAK_MB:`` line when
    ``peak_tracemalloc_mb`` is supplied, so any external readers still work.
    """
    print(f"METRICS_JSON:{json.dumps(metrics)}")
    if "peak_tracemalloc_mb" in metrics:
        print(f"PEAK_MB:{metrics['peak_tracemalloc_mb']}")
