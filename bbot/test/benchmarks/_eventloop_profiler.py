#!/usr/bin/env python3
"""
Event-loop saturation diagnostic — wraps a full BBOT scan to measure:

  1. Which tasks/coroutines hold the loop the longest (blocking detection)
  2. How many tasks are pending at any given time
  3. Per-module breakdown of loop time consumption

This is a diagnostic utility, not a pytest-benchmark test. The leading
underscore tells pytest not to collect it; run it directly:

    uv run python bbot/test/benchmarks/_eventloop_profiler.py -y -p spider -f subdomain-enum -t example.com

Output lands under `./eventloop_profile/<timestamp>/`:

  - eventloop_report.txt — top coroutines by total/max loop time, slow-step log, task timeline
  - slow_steps.csv       — every callback longer than SLOW_CALLBACK_THRESHOLD
  - task_timeline.csv    — concurrent task count sampled every REPORT_INTERVAL seconds
"""

import asyncio
import atexit
import collections
import signal
import sys
import time
import threading
from datetime import datetime
from pathlib import Path

# ── Configuration ───────────────────────────────────────────────────────────
SLOW_CALLBACK_THRESHOLD = 0.05  # 50ms - flag callbacks slower than this
REPORT_INTERVAL = 15  # seconds between periodic reports
OUTPUT_DIR = Path("./eventloop_profile")


class EventLoopProfiler:
    """Instruments asyncio tasks to measure per-coroutine loop time consumption."""

    def __init__(self, loop, output_dir):
        self.loop = loop
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Per-coroutine stats: qualname -> {total_time, count, max_time}
        self.coro_times = collections.defaultdict(lambda: {"total_time": 0.0, "count": 0, "max_time": 0.0})
        # Slow step log: (elapsed, duration, coro_name)
        self.slow_steps = []
        # Task count timeline: (elapsed, num_tasks)
        self.task_counts = []
        # Task detail timeline: (elapsed, {coro_name: count})
        self.task_detail_timeline = []

        self.start_time = time.monotonic()
        self.total_steps = 0
        self.total_step_time = 0.0

        self._lock = threading.Lock()

    def _get_task_coro_name(self, task):
        """Get a meaningful name for a task's coroutine."""
        coro = task.get_coro()
        if coro is None:
            return task.get_name()
        qualname = getattr(coro, "__qualname__", None)
        if qualname:
            # Try to get the module name from cr_frame
            frame = getattr(coro, "cr_frame", None)
            if frame:
                filename = frame.f_code.co_filename
                # Extract just the relevant part of the path
                if "bbot/" in filename:
                    short_path = filename[filename.index("bbot/") :]
                    return f"{short_path}:{qualname}"
            return qualname
        return task.get_name()

    def install(self):
        """Patch the loop's create_task and Handle._run to time coroutine steps."""
        profiler = self

        # Map task id -> coroutine name (set at creation time)
        self._task_names = {}

        # Patch loop.create_task to record coroutine names
        original_create_task = self.loop.create_task

        def patched_create_task(coro, *, name=None, context=None):
            if context is not None:
                task = original_create_task(coro, name=name, context=context)
            else:
                task = original_create_task(coro, name=name)
            coro_name = profiler._get_task_coro_name(task)
            profiler._task_names[id(task)] = coro_name
            # Clean up when task is done
            task.add_done_callback(lambda t: profiler._task_names.pop(id(t), None))
            return task

        self.loop.create_task = patched_create_task

        # Also patch asyncio.ensure_future / create_task at module level
        _original_ensure_future = asyncio.ensure_future

        def patched_ensure_future(coro_or_future, *, loop=None):
            result = _original_ensure_future(coro_or_future, loop=loop)
            if isinstance(result, asyncio.Task):
                coro_name = profiler._get_task_coro_name(result)
                profiler._task_names[id(result)] = coro_name
                result.add_done_callback(lambda t: profiler._task_names.pop(id(t), None))
            return result

        asyncio.ensure_future = patched_ensure_future

        # Patch Handle._run to time callbacks, resolving task names from our map
        original_handle_run = asyncio.Handle._run

        def profiled_handle_run(handle):
            # Try to identify which task this handle belongs to
            cb = getattr(handle, "_callback", None)
            cb_name = None

            # TaskStepMethWrapper has a __self__ that is the Task
            task_self = getattr(cb, "__self__", None)
            if task_self is not None and isinstance(task_self, asyncio.Task):
                cb_name = profiler._task_names.get(id(task_self))
                if cb_name is None:
                    cb_name = profiler._get_task_coro_name(task_self)

            if cb_name is None:
                cb_name = getattr(cb, "__qualname__", None) or getattr(cb, "__name__", None) or str(cb)

            start = time.monotonic()
            original_handle_run(handle)
            duration = time.monotonic() - start

            with profiler._lock:
                profiler.total_steps += 1
                profiler.total_step_time += duration

                stats = profiler.coro_times[cb_name]
                stats["total_time"] += duration
                stats["count"] += 1
                if duration > stats["max_time"]:
                    stats["max_time"] = duration

                if duration > SLOW_CALLBACK_THRESHOLD:
                    elapsed = time.monotonic() - profiler.start_time
                    profiler.slow_steps.append((elapsed, duration, cb_name))

        asyncio.Handle._run = profiled_handle_run

        print(f"[eventloop-profiler] Installed. Slow threshold: {SLOW_CALLBACK_THRESHOLD * 1000:.0f}ms")
        print(f"[eventloop-profiler] Output dir: {self.output_dir}")

    def sample_tasks(self):
        """Sample the current task breakdown."""
        try:
            tasks = asyncio.all_tasks(self.loop)
            elapsed = time.monotonic() - self.start_time
            self.task_counts.append((elapsed, len(tasks)))

            # Group by coroutine name
            task_names = collections.Counter()
            for task in tasks:
                name = self._get_task_coro_name(task)
                # Simplify: extract just the class.method or module
                parts = name.split(":")
                if len(parts) > 1:
                    short = parts[-1]  # qualname
                else:
                    short = name
                task_names[short] += 1

            self.task_detail_timeline.append((elapsed, dict(task_names)))
            return len(tasks), task_names
        except Exception:
            return 0, collections.Counter()

    def write_report(self):
        """Write the final profiling report."""
        elapsed = time.monotonic() - self.start_time

        with self._lock:
            coro_times = dict(self.coro_times)
            slow_steps = list(self.slow_steps)

        lines = []
        lines.append("Event Loop Profiling Report")
        lines.append("=" * 80)
        lines.append(f"Duration: {elapsed:.1f}s ({elapsed / 60:.1f}m)")
        lines.append(f"Total task steps: {self.total_steps:,}")
        lines.append(f"Total step time: {self.total_step_time:.1f}s")
        lines.append(f"Avg step time: {self.total_step_time / max(self.total_steps, 1) * 1000:.3f}ms")
        lines.append(f"Slow steps (>{SLOW_CALLBACK_THRESHOLD * 1000:.0f}ms): {len(slow_steps)}")
        lines.append("")

        # ── Top coroutines by total time ────────────────────────
        lines.append("TOP 40 COROUTINES BY TOTAL EVENT LOOP TIME")
        lines.append("-" * 80)
        lines.append(f"{'Total(s)':>10s} {'Steps':>8s} {'Avg(ms)':>10s} {'Max(ms)':>10s} {'%loop':>7s}  Coroutine")
        sorted_coros = sorted(coro_times.items(), key=lambda x: x[1]["total_time"], reverse=True)
        for name, stats in sorted_coros[:40]:
            pct = (stats["total_time"] / max(self.total_step_time, 0.001)) * 100
            avg_ms = (stats["total_time"] / max(stats["count"], 1)) * 1000
            lines.append(
                f"{stats['total_time']:>10.2f} {stats['count']:>8d} {avg_ms:>10.3f} {stats['max_time'] * 1000:>10.1f} {pct:>6.1f}%  {name}"
            )
        lines.append("")

        # ── Top coroutines by max single step ───────────────────
        lines.append("TOP 20 COROUTINES BY MAX SINGLE STEP TIME (blocking suspects)")
        lines.append("-" * 80)
        lines.append(f"{'Max(ms)':>10s} {'Steps':>8s} {'Total(s)':>10s}  Coroutine")
        sorted_max = sorted(coro_times.items(), key=lambda x: x[1]["max_time"], reverse=True)
        for name, stats in sorted_max[:20]:
            lines.append(
                f"{stats['max_time'] * 1000:>10.1f} {stats['count']:>8d} {stats['total_time']:>10.2f}  {name}"
            )
        lines.append("")

        # ── Slow step log ───────────────────────────────────────
        lines.append(f"SLOW STEP LOG (>{SLOW_CALLBACK_THRESHOLD * 1000:.0f}ms, last 200)")
        lines.append("-" * 80)
        for elapsed_t, duration, name in slow_steps[-200:]:
            lines.append(f"  t={elapsed_t:>8.1f}s  {duration * 1000:>8.1f}ms  {name}")
        lines.append("")

        # ── Task count timeline ─────────────────────────────────
        if self.task_counts:
            lines.append("TASK COUNT TIMELINE (sampled every 15s)")
            lines.append("-" * 80)
            peak_tasks = max(tc[1] for tc in self.task_counts)
            lines.append(f"Peak concurrent tasks: {peak_tasks}")
            for elapsed_t, count in self.task_counts:
                bar = "#" * min(count, 60)
                lines.append(f"  t={elapsed_t:>8.1f}s  tasks={count:>4d}  {bar}")
        lines.append("")

        # ── Task breakdown at peak ──────────────────────────────
        if self.task_detail_timeline:
            # Find the sample with the most tasks
            peak_sample = max(self.task_detail_timeline, key=lambda x: sum(x[1].values()))
            elapsed_t, detail = peak_sample
            lines.append(f"TASK BREAKDOWN AT PEAK (t={elapsed_t:.1f}s, {sum(detail.values())} tasks)")
            lines.append("-" * 80)
            for name, count in sorted(detail.items(), key=lambda x: -x[1])[:30]:
                bar = "#" * min(count, 40)
                lines.append(f"  {count:>4d}  {bar}  {name}")
        lines.append("")

        report = "\n".join(lines)

        report_path = self.output_dir / "eventloop_report.txt"
        with open(report_path, "w") as f:
            f.write(report)

        # Write slow steps as CSV
        csv_path = self.output_dir / "slow_steps.csv"
        with open(csv_path, "w") as f:
            f.write("elapsed_s,duration_ms,coroutine\n")
            for elapsed_t, duration, name in slow_steps:
                safe_name = name.replace(",", ";")
                f.write(f"{elapsed_t:.1f},{duration * 1000:.1f},{safe_name}\n")

        # Write task timeline as CSV
        task_csv = self.output_dir / "task_timeline.csv"
        with open(task_csv, "w") as f:
            f.write("elapsed_s,num_tasks\n")
            for elapsed_t, count in self.task_counts:
                f.write(f"{elapsed_t:.1f},{count}\n")

        print(f"\n[eventloop-profiler] Report written to {report_path}")
        # Print the full report to stdout
        print(report)

        return report_path


async def periodic_sampler(profiler, stop_event):
    """Periodically sample task counts and print status."""
    while not stop_event.is_set():
        num_tasks, task_names = profiler.sample_tasks()

        top = task_names.most_common(6)
        top_str = ", ".join(f"{name.split('.')[-1]}={count}" for name, count in top)
        elapsed = time.monotonic() - profiler.start_time
        slow_count = len(profiler.slow_steps)
        print(f"[profiler t={elapsed:.0f}s] tasks={num_tasks} slow_steps={slow_count} | {top_str}")

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=REPORT_INTERVAL)
        except asyncio.TimeoutError:
            pass


async def run_scan(bbot_args, profiler):
    from bbot.scanner import Scanner
    from bbot.scanner.preset import Preset

    sys.argv = ["bbot"] + list(bbot_args)
    preset = Preset(_log=True, name="eventloop_profile")
    preset.parse_args()
    baked_preset = preset.bake()
    scanner = Scanner(preset=baked_preset)

    stop_event = asyncio.Event()
    sampler = asyncio.create_task(periodic_sampler(profiler, stop_event))

    try:
        await scanner.async_start_without_generator()
    except KeyboardInterrupt:
        print("\n[profiler] Interrupted")
    except Exception as e:
        print(f"\n[profiler] Scan error: {e}")
        import traceback

        traceback.print_exc()
    finally:
        stop_event.set()
        await sampler


def main():
    bbot_args = sys.argv[1:]
    if not bbot_args:
        print("Usage: python bbot/test/benchmarks/_eventloop_profiler.py [bbot args...]")
        print(
            "Example: python bbot/test/benchmarks/_eventloop_profiler.py -y -p spider -f subdomain-enum -t example.com"
        )
        sys.exit(1)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = OUTPUT_DIR / ts
    output_dir.mkdir(parents=True, exist_ok=True)

    print("Event Loop Saturation Diagnostic")
    print(f"Slow callback threshold: {SLOW_CALLBACK_THRESHOLD * 1000:.0f}ms")
    print(f"Output: {output_dir}")
    print()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    profiler = EventLoopProfiler(loop, output_dir)
    profiler.install()

    def write_on_exit(*args):
        profiler.write_report()
        sys.exit(0)

    signal.signal(signal.SIGINT, write_on_exit)
    signal.signal(signal.SIGTERM, write_on_exit)
    atexit.register(profiler.write_report)

    try:
        loop.run_until_complete(run_scan(bbot_args, profiler))
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        profiler.write_report()


if __name__ == "__main__":
    main()
