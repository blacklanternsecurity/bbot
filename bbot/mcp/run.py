"""
Runs BBOT scans in-process through `bbot.scanner.Scanner`.

The execution model, and why each part of it is the way it is:

  - **In-process, not shelled out.** `Scanner` yields live event objects, which is
    the only way to read partial results while a scan is still going.
  - **A dedicated event loop on its own thread.** BBOT has synchronous stretches
    that would otherwise occupy the MCP server's request loop and stall every
    other tool call.
  - **Scans run in the background.** A worthwhile BBOT scan takes tens of minutes
    to hours, far longer than a tool call should block for. Launching returns a
    `scan_id` immediately.
  - **Accumulators live on the handle**, not in the collector. A scan that is
    cancelled or times out still hands back everything it found.
  - **One scan at a time.** A `Scanner` reaches shared DNS caches, the shared
    resolver, `~/.bbot` state and the dependency installer's lock, so two live
    scans in one process can wedge each other. A second scan queues rather than
    running alongside.
"""

import asyncio
import logging
import threading
import time
import uuid
from contextlib import suppress
from dataclasses import dataclass, field

from bbot.mcp.derive import resolve_bundled_includes

log = logging.getLogger("bbot.mcp.run")

# Event types worth keeping past the returned-event cap. BBOT front-loads bulk
# discovery and produces its conclusions late, so a cap reached in the first
# minute would otherwise discard exactly the events the scan was run for.
HIGH_SIGNAL_TYPES = frozenset(
    {
        "FINDING",
        "TECHNOLOGY",
        "STORAGE_BUCKET",
        "CODE_REPOSITORY",
        "WEB_PARAMETER",
        "PASSWORD",
        "HASHED_PASSWORD",
        "USERNAME",
        "EMAIL_ADDRESS",
        "WAF",
        "AZURE_TENANT",
        "MOBILE_APP",
        "VIRTUAL_HOST",
        "SOCIAL",
    }
)

# Statuses that mean the scan is still going, so stopping it is meaningful.
# FINISHING is deliberately excluded: the modules' finishing stages are the last
# of the real work, not an idle tail.
UNFINISHED_STATUSES = frozenset({"STARTING", "RUNNING"})

# A memory backstop far above any sane cap, not a result limit.
ABSOLUTE_EVENT_CEILING = 25_000
DEFAULT_MAX_EVENTS = 2000
# A runaway backstop, not a budget: a real scan on a large org runs for hours.
# Hitting this returns everything found so far rather than discarding it.
DEFAULT_TIMEOUT_SECONDS = 21600.0
TEARDOWN_TIMEOUT_SECONDS = 60.0
PROGRESS_INTERVAL_SECONDS = 60.0
# A bound on the queue depth, so nobody stacks up scans they will never read.
MAX_ACTIVE_SCANS = 3

SCANS = {}
_SCAN_TASKS = {}
_BACKGROUND_TASKS = set()

_SCAN_LOOP = None
_SCAN_LOOP_THREAD = None
_SCAN_LOOP_READY = threading.Event()
_SCAN_LOOP_GUARD = threading.Lock()
_SCAN_LOCK = None


def _serve_scan_loop():
    global _SCAN_LOOP
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    _SCAN_LOOP = loop
    _SCAN_LOOP_READY.set()
    loop.run_forever()


def scan_event_loop():
    """The loop scans run on. Keeps BBOT's blocking stretches off the MCP loop."""
    global _SCAN_LOOP, _SCAN_LOOP_THREAD
    if _SCAN_LOOP is None:
        with _SCAN_LOOP_GUARD:
            if _SCAN_LOOP is None:
                _SCAN_LOOP_READY.clear()
                t = threading.Thread(target=_serve_scan_loop, name="bbot-mcp-scans", daemon=True)
                t.start()
                _SCAN_LOOP_THREAD = t
        _SCAN_LOOP_READY.wait()
    if _SCAN_LOOP is None:  # pragma: no cover - the thread either starts or raises
        raise RuntimeError("BBOT scan loop failed to start")
    return _SCAN_LOOP


def scan_lock():
    """The single-scan lock, created on the loop that actually runs the scans."""
    global _SCAN_LOCK
    if _SCAN_LOCK is None:
        _SCAN_LOCK = asyncio.Lock()
    return _SCAN_LOCK


def default_omitted_types():
    """Event types this BBOT build withholds from output by default.

    The sharpest edge in BBOT's API for a consumer like this. Omitted events are
    still produced and still drive every downstream module, they are simply never
    handed to an output module, and `Scanner.async_start()` is one (the internal
    `python` module). So a scan can find thousands of URL_UNVERIFIEDs and return
    none of them, which reads exactly like finding nothing.
    """
    try:
        from bbot.scanner import Preset

        omitted = Preset(_log=False).core.default_config.get("omit_event_types") or []
    except Exception as e:
        # An empty list means "BBOT omits nothing", which is a real and different
        # answer from "the lookup failed" -- say which one this is.
        log.warning("could not read omit_event_types from BBOT's defaults: %s: %s", type(e).__name__, e)
        return []
    return sorted(str(item) for item in omitted)


def omission_note(event_types, config):
    """Warn when a scan asks for types this build omits from output by default."""
    if "omit_event_types" in (config or {}):  # the caller already owns the list
        return ""
    omitted = set(default_omitted_types())
    wanted = sorted(t for t in (event_types or []) if t in omitted)
    if not wanted:
        return ""
    return (
        f"{', '.join(wanted)} {'is' if len(wanted) == 1 else 'are'} in BBOT's default omit_event_types, so "
        "this scan will run the modules that produce them and hand back none of them. To receive them, "
        'pass config={"omit_event_types": []} (or a shorter list). '
        f"This build omits: {', '.join(sorted(omitted))}."
    )


def scanner_kwargs(composed, blacklist=None, output_dir=None, strict_scope=False):
    """Map a composed preset dict onto `Scanner(...)` keyword arguments.

    `include:` becomes `presets`, resolved to the shipped preset files rather than
    left as bare names: the scan has to run the configuration that was advertised,
    and bare names go through a search path anything can add a directory to.
    """
    resolved = resolve_bundled_includes(composed)
    kwargs = {}
    if resolved.get("include"):
        kwargs["presets"] = list(resolved["include"])
    for key in (
        "modules",
        "output_modules",
        "exclude_modules",
        "exclude_output_modules",
        "flags",
        "require_flags",
        "exclude_flags",
    ):
        if resolved.get(key):
            kwargs[key] = list(resolved[key])
    config = resolved.get("config") or {}
    if strict_scope:
        # BBOT treats subdomains of a target as in-scope by default, which is
        # usually what you want and occasionally very much not. Merged rather
        # than assigned so a preset's own config survives.
        from bbot.core.config.merge import deep_merge

        config = deep_merge(config, {"scope": {"strict": True}})
    if config:
        kwargs["config"] = config
    if blacklist:
        kwargs["blacklist"] = list(blacklist)
    if output_dir:
        kwargs["output_dir"] = str(output_dir)
    return kwargs


def event_record(event):
    """Normalize a BBOT event into a compact, JSON-safe record."""
    data = getattr(event, "data", None)
    tags = getattr(event, "tags", None)
    event_type = str(getattr(event, "type", "") or "")
    record = {
        "type": event_type,
        "host": str(getattr(event, "host", "") or "") or None,
        "module": str(getattr(event, "module", "") or "") or None,
        "scope": str(getattr(event, "scope_description", "") or "") or None,
        "tags": sorted(str(tag) for tag in tags) if isinstance(tags, (list, set, tuple)) else [],
        "data": data if isinstance(data, (dict, str, int, float, bool)) else str(data),
    }
    # BBOT writes a plain-English sentence on every event explaining how it got
    # there, and `discovery_path` is that sentence for every ancestor back to the
    # scan's seed. It is what `output.json` carries, and for a finding it is the
    # difference between "there is a bug here" and "here is the route that
    # reached it" -- which is what a reader needs to judge and to reproduce it.
    # Carried on high-signal events only: on a flood of DNS_NAMEs the chain costs
    # far more than it says.
    if event_type in HIGH_SIGNAL_TYPES:
        context = str(getattr(event, "discovery_context", "") or "")
        if context:
            record["why"] = context
        path = getattr(event, "discovery_path", None)
        if path:
            record["discovery_path"] = [str(step) for step in path]
        # The complete BBOT event, exactly as it appears in the scan's
        # output.json. Held in memory but never returned unless asked for: it is
        # several times the size of everything else on this record, and almost
        # every question about a finding is answered without it.
        to_json = getattr(event, "json", None)
        if callable(to_json):
            with suppress(Exception):
                record["_full"] = to_json()
    return record


def module_activity(scanner):
    """Summarize which modules are busy, as 'module(in->out)' for the active ones."""
    modules = getattr(scanner, "modules", None)
    if not isinstance(modules, dict):
        return ""
    busy = []
    errored = []
    for name, module in modules.items():
        try:
            status = module.status
        except Exception:
            continue
        if not isinstance(status, dict):
            continue
        incoming = int(status.get("events", {}).get("incoming", 0) or 0)
        outgoing = int(status.get("events", {}).get("outgoing", 0) or 0)
        tasks = int(status.get("tasks", 0) or 0)
        if status.get("errored"):
            errored.append(str(name))
        queued = incoming + outgoing + tasks
        if queued > 0:
            busy.append((queued, f"{name}({incoming}->{outgoing}" + (f",{tasks}t" if tasks else "") + ")"))
    busy.sort(key=lambda item: -item[0])
    summary = "  queues: " + " ".join(label for _, label in busy[:6]) if busy else ""
    if errored:
        summary += f"  errored: {', '.join(sorted(errored)[:4])}"
    return summary


async def stop_scan(scanner):
    """Stop a scan and wait for it to actually be down.

    `Scanner.stop()` is synchronous: it fires `async_stop()` onto the loop and
    returns None, so awaiting its result waits for nothing. `async_stop()` is the
    one that cancels tasks, drains queues and kills child processes.
    """
    async_stop = getattr(scanner, "async_stop", None)
    if async_stop is not None:
        with suppress(Exception):
            await async_stop()
        return
    stop = getattr(scanner, "stop", None)
    if stop is None:
        return
    with suppress(Exception):
        result = stop()
        if asyncio.iscoroutine(result):
            await result


async def bounded_stop(scanner, timeout=15.0):
    """Stop a scan without letting BBOT's cleanup block indefinitely."""
    with suppress(Exception):
        await asyncio.wait_for(stop_scan(scanner), timeout=timeout)


async def progress_loop(counts, scanner=None, label=""):
    """Log a one-line heartbeat every interval until cancelled. A long scan has to
    be visibly alive."""
    start = time.monotonic()
    named = f"scan {label}" if label else "scan"
    while True:
        await asyncio.sleep(PROGRESS_INTERVAL_SECONDS)
        total = sum(counts.values())
        top = ", ".join(f"{t}={c}" for t, c in sorted(counts.items(), key=lambda kv: -kv[1])[:5])
        activity = module_activity(scanner) if scanner is not None else ""
        log.info(
            "%s running: %d events%s - elapsed %.0fs%s",
            named,
            total,
            f" - {top}" if top else "",
            time.monotonic() - start,
            activity,
        )


async def collect_events(scanner, max_events, event_types, counts, events, handle=None):
    """Drain a scan to its end, accumulating into the caller's lists.

    The accumulators belong to the caller so a scan abandoned at the timeout still
    hands back everything it found.

    The cap bounds what is RETURNED, never how long the scan runs.
    """
    wanted = set(event_types or [])
    async for event in scanner.async_start():
        event_type = str(getattr(event, "type", "") or "")
        counts[event_type] = counts.get(event_type, 0) + 1
        if handle is not None:
            handle.last_event_at = time.monotonic()
        if wanted and event_type not in wanted:
            continue
        # Out-of-scope events are real discoveries but they are not the answer
        # to the question a pseudotool was asked. A subdomain scan legitimately
        # emits the target's nameservers, its mail exchangers, and affiliate
        # infrastructure found in certificates -- returning those alongside the
        # actual subdomains buries the result in things the caller did not ask
        # for and does not own.
        if str(getattr(event, "scope_description", "") or "") != "in-scope":
            continue
        if len(events) >= ABSOLUTE_EVENT_CEILING:
            continue
        if len(events) < max_events or event_type in HIGH_SIGNAL_TYPES:
            events.append(event_record(event))
    # The stream ending means BBOT finished the scan and ran its own cleanup. Do
    # not stop it here: a scan's status only ever moves forward and ABORTED
    # outranks FINISHED, so async_stop() on a finished scan rewrites FINISHED to
    # ABORTED and every successful scan then reports as incomplete.
    if str(getattr(scanner, "status", "") or "").upper() in UNFINISHED_STATUSES:
        await bounded_stop(scanner)


@dataclass
class ScanHandle:
    """A scan running in the background, and everything it has found so far.

    The accumulators here are live, so progress and partial results are readable
    at any moment rather than only at the end.
    """

    scan_id: str
    targets: list
    selection: str
    started_at: float
    queued_at: float = 0.0
    counts: dict = field(default_factory=dict)
    events: list = field(default_factory=list)
    scanner: object = None
    last_event_at: float = 0.0
    state: str = "running"
    error: str = ""
    result: dict = None
    finished_at: float = 0.0
    task: object = field(default=None, repr=False)
    conflicts: list = field(default_factory=list)
    # scans this one is waiting on, at the moment it was launched
    queued_behind: list = field(default_factory=list)

    @property
    def elapsed(self):
        return (self.finished_at or time.monotonic()) - self.started_at

    @property
    def running(self):
        return self.state in {"running", "queued", "stopping"}

    @property
    def scanning(self):
        return self.state == "running"

    def progress(self):
        report = {
            "scan_id": self.scan_id,
            "state": self.state,
            "targets": self.targets,
            "selection": self.selection,
            "elapsed_seconds": round(self.elapsed, 1),
            "events_seen": sum(self.counts.values()),
            "events_available": len(self.events),
            "counts_by_type": dict(sorted(self.counts.items())),
        }
        if self.scanner is not None:
            report["scan_status"] = str(getattr(self.scanner, "status", "") or "UNKNOWN")
        if self.state == "queued":
            report["waiting_seconds"] = round(time.monotonic() - (self.queued_at or self.started_at), 1)
            report["note"] = "waiting for the running scan to finish; BBOT runs one scan at a time"
        elif self.scanning:
            busy = module_activity(self.scanner).strip() if self.scanner is not None else ""
            report["busy"] = busy
            if self.last_event_at:
                report["idle_seconds"] = round(time.monotonic() - self.last_event_at, 1)
            if not busy:
                # Empty queues do not mean finished: BBOT then runs each module's
                # finishing stage, which keeps working and keeps emitting.
                report["note"] = (
                    "no module queues have work outstanding. A scan is not done when its queues empty: "
                    "BBOT then runs each module's finishing stage, which can keep working, and keep "
                    "producing events, for a long time on a large scan. Let it run; scan_stop keeps "
                    "everything found so far if you would rather not wait."
                )
        if self.conflicts:
            report["warnings"] = self.conflicts
        if self.error:
            report["error"] = self.error
        if self.result:
            report["scan_status"] = self.result.get("scan_status")
        return report


async def settle_scanner(handle):
    """Stop the underlying scan and wait for it to actually be done.

    Nothing that starts after this should share the process with a scan still
    winding down. This blocks only the queue behind it, never a caller.
    """
    scanner = handle.scanner
    if scanner is None:
        return
    started = time.monotonic()
    with suppress(Exception):
        await bounded_stop(scanner, timeout=TEARDOWN_TIMEOUT_SECONDS)
    for _ in range(int(TEARDOWN_TIMEOUT_SECONDS * 2)):
        status = str(getattr(scanner, "status", "") or "").upper()
        if status not in UNFINISHED_STATUSES and status != "ABORTING":
            break
        await asyncio.sleep(0.5)
    waited = time.monotonic() - started
    if waited > 1:
        log.info("scan %s finished tearing down after %.0fs", handle.scan_id, waited)


def scan_result(targets, scanner, counts, events, timed_out=False, timeout=0.0, requested_modules=None):
    """Summarize how a scan finished, and whether to trust it."""
    truncated = sum(counts.values()) > len(events)
    # BBOT knows whether the scan ran (FINISHED) or gave up (ABORTED / FAILED).
    # Unsaid, "found nothing" is indistinguishable from "never ran".
    status = str(getattr(scanner, "status", "") or "UNKNOWN")
    healthy = status.upper() in {"FINISHED", "FINISHING", "UNKNOWN"}
    active_modules = sorted(getattr(scanner, "modules", {}) or {})
    log.info(
        "scan %s: %d events (%s) status=%s modules=%d",
        f"cut short at {timeout:.0f}s" if timed_out else "complete",
        len(events),
        "truncated" if truncated else "full",
        status,
        len(active_modules),
    )
    if timed_out:
        pass  # already reported by the caller; not a health problem
    elif not healthy:
        log.warning("scan finished with non-healthy status=%s - results are probably incomplete", status)
    elif not events or all(event.get("type") == "SCAN" for event in events):
        log.warning(
            "scan produced no findable events (status=%s, %d modules enabled) - "
            "check module API keys and dependencies before trusting this as 'nothing found'",
            status,
            len(active_modules),
        )
    result = {
        "ok": True,
        "targets": targets,
        "scan_status": status,
        "modules_enabled": len(active_modules),
        "event_count": len(events),
        "counts_by_type": dict(sorted(counts.items())),
        "truncated": truncated,
    }
    # A module whose setup fails is dropped and the scan runs without it. Unsaid,
    # a scan missing half its enumeration reads like a thorough one that found less.
    unavailable = sorted(set(requested_modules or []) - set(active_modules))
    if unavailable:
        log.warning("requested modules did not run: %s", ", ".join(unavailable))
        result["modules_unavailable"] = unavailable
        result["modules_unavailable_note"] = (
            "these requested modules are not in the scan: their setup failed, usually a missing API key or "
            "dependency. Results are narrower than requested."
        )
    if timed_out:
        result["timed_out"] = True
        result["note"] = (
            f"the scan was still running at {timeout:.0f}s and was abandoned; these are the events found up "
            "to that point. BBOT produces its most valuable events late, so consider re-running with a "
            "longer timeout_seconds before concluding."
        )
    return result


def _build_scanner(targets, scan_kwargs):
    """Construct the BBOT Scanner. The single seam tests substitute."""
    from bbot.scanner import Scanner

    return Scanner(*targets, **scan_kwargs)


async def run_scan(targets, scan_kwargs, max_events, event_types, timeout, handle=None):
    """Build a Scanner, drain it, and summarize. Returns the result dict."""
    if not targets:
        raise ValueError("provide at least one target")

    requested_modules = [str(name) for name in scan_kwargs.get("modules") or []]
    counts = handle.counts if handle is not None else {}
    events = handle.events if handle is not None else []
    scanner = _build_scanner(targets, scan_kwargs)
    if handle is not None:
        handle.scanner = scanner
    log.info(
        "scan started: targets=%s  %s  max_events=%d timeout=%.0fs",
        ", ".join(targets),
        handle.selection if handle else "",
        max_events,
        timeout,
    )

    collector = asyncio.ensure_future(collect_events(scanner, max_events, event_types, counts, events, handle=handle))
    progress = asyncio.ensure_future(progress_loop(counts, scanner, handle.scan_id if handle else ""))
    try:
        done, _pending = await asyncio.wait({collector}, timeout=timeout)
    finally:
        progress.cancel()

    if collector not in done:
        # Returning early would release the scan lock while BBOT is still running,
        # letting the next scan start alongside a very much alive one. Wait for it.
        collector.cancel()
        with suppress(asyncio.CancelledError, Exception):
            await asyncio.wait_for(asyncio.shield(collector), timeout=1.0)
        if handle is not None:
            handle.state = "stopping"
            await settle_scanner(handle)
        else:
            with suppress(Exception):
                await bounded_stop(scanner, timeout=TEARDOWN_TIMEOUT_SECONDS)
        # SCAN is BBOT's own bookkeeping event, emitted as the scan opens whether
        # or not anything is found. Counting it would make a scan that discovered
        # nothing read as having produced one event.
        seen = sum(count for event_type, count in counts.items() if event_type != "SCAN")
        log.warning("scan abandoned after %.0fs; returning the %d events found so far", timeout, seen)
        if seen == 0:
            raise ValueError(
                f"the scan produced nothing in {timeout:.0f}s. If this is the first BBOT run its module "
                "dependencies may still be installing, which needs sudo and will hang here. Otherwise "
                "narrow the targets or the capability selection."
            )
        return scan_result(
            targets, scanner, counts, events, timed_out=True, timeout=timeout, requested_modules=requested_modules
        )
    return scan_result(targets, scanner, counts, events, requested_modules=requested_modules)


async def drive_scan(handle, scan_kwargs, max_events, event_types, timeout):
    """Run a scan to its end in the background, recording how it finished.

    Waits for any scan already running to finish first; `state` reports that as
    `queued` so a caller checking in can tell waiting from working.
    """
    handle.task = asyncio.current_task()
    try:
        async with scan_lock():
            handle.state = "running"
            # elapsed should measure the scan, not the time it spent waiting
            handle.started_at = time.monotonic()
            try:
                result = await run_scan(handle.targets, scan_kwargs, max_events, event_types, timeout, handle=handle)
            except asyncio.CancelledError:
                # Cancelling the collector does not stop BBOT: the Scanner keeps
                # its own tasks and threads. Releasing the lock here would let the
                # next scan start alongside a live one, exactly what serialising
                # is meant to prevent. Shielded, so the cancel that got us here
                # does not also cancel the teardown.
                handle.state = "stopping"
                await asyncio.shield(settle_scanner(handle))
                raise
    except asyncio.CancelledError:
        handle.state = "stopped"
        handle.finished_at = time.monotonic()
        raise
    except Exception as e:  # a failed scan must not take the server with it
        handle.state = "failed"
        handle.error = f"{type(e).__name__}: {e}"
        handle.finished_at = time.monotonic()
        log.warning("scan %s failed: %s", handle.scan_id, handle.error)
        return
    handle.result = result
    handle.state = "timed_out" if result.get("timed_out") else "finished"
    handle.finished_at = time.monotonic()


async def cancel_scan(handle):
    task = handle.task
    if task is None or task.done():
        return
    task.cancel()
    with suppress(asyncio.CancelledError):
        await task


def launch(targets, scan_kwargs, selection, max_events, event_types, timeout, conflicts=None):
    """Start a scan in the background. Returns its `ScanHandle`.

    Raises `RuntimeError` when the queue is full.
    """
    active = [h for h in SCANS.values() if h.running]
    if len(active) >= MAX_ACTIVE_SCANS:
        scanning = [h.scan_id for h in active if h.scanning]
        waiting = [h.scan_id for h in active if not h.scanning]
        raise RuntimeError(
            f"the scan queue is full: {', '.join(scanning) or 'none'} scanning, "
            f"{', '.join(waiting) or 'none'} queued behind it. One scan runs at a time, so another would "
            "only wait. Read what the running one has found with scan_results, or free a slot with scan_stop."
        )

    now = time.monotonic()
    queued_behind = [h.scan_id for h in SCANS.values() if h.running]
    handle = ScanHandle(
        scan_id=uuid.uuid4().hex[:8],
        targets=list(targets),
        selection=selection,
        started_at=now,
        queued_at=now,
        state="queued" if queued_behind else "running",
        conflicts=list(conflicts or []),
        queued_behind=queued_behind,
    )
    SCANS[handle.scan_id] = handle
    task = asyncio.run_coroutine_threadsafe(
        drive_scan(handle, scan_kwargs, max(1, int(max_events)), event_types, max(1.0, float(timeout))),
        scan_event_loop(),
    )
    _BACKGROUND_TASKS.add(task)
    task.add_done_callback(_BACKGROUND_TASKS.discard)
    _SCAN_TASKS[handle.scan_id] = task
    return handle


def get_handle(scan_id):
    handle = SCANS.get((scan_id or "").strip())
    if handle is None:
        raise KeyError(f"unknown scan_id {scan_id!r}; known: {', '.join(SCANS) or 'none'}")
    return handle


async def request_stop(handle):
    """Abandon a running scan, keeping everything it has found."""
    task = _SCAN_TASKS.get(handle.scan_id)
    if handle.running and task is not None and not task.done():
        stop = asyncio.run_coroutine_threadsafe(cancel_scan(handle), scan_event_loop())
        try:
            await asyncio.wait_for(asyncio.wrap_future(stop), timeout=15.0)
        except (TimeoutError, asyncio.TimeoutError):
            handle.state = "stopping"
            handle.error = handle.error or "stop requested; BBOT is still winding down"
    if handle.running and (task is None or task.done()):
        handle.state = "stopped"
        handle.finished_at = time.monotonic()
    # What it found is still worth keeping.
    if handle.state == "stopped" and handle.result is None and handle.scanner is not None:
        handle.result = scan_result(handle.targets, handle.scanner, handle.counts, handle.events)
    log.info("scan %s %s after %.0fs with %d events", handle.scan_id, handle.state, handle.elapsed, len(handle.events))
    return handle


def shutdown_scan_loop(timeout=10.0):
    """Tear down the scan loop and its Rust runtimes before interpreter finalization.

    blasthttp, blastdns, and cloudcheck each spin up a tokio async runtime with
    background worker threads. Those workers call into Python through pyo3. When
    the interpreter starts Py_Finalize while a worker is mid-call, pyo3 panics at
    interpreter_lifecycle.rs and the process crashes. Stopping the scans and
    dropping the Rust client references here, while the interpreter is still
    alive, prevents that cascade.
    """
    global _SCAN_LOOP, _SCAN_LOOP_THREAD
    loop = _SCAN_LOOP
    if loop is None:
        return

    async def _stop_all():
        for handle in list(SCANS.values()):
            if not handle.running:
                continue
            with suppress(Exception):
                await cancel_scan(handle)
        for handle in list(SCANS.values()):
            scanner = handle.scanner
            if scanner is None:
                continue
            helpers = getattr(scanner, "helpers", None)
            if helpers is None:
                continue
            # Drop references to Rust extensions so their tokio runtimes shut
            # down while the interpreter is still alive.
            for attr in ("_blasthttp_client", "_cloudcheck", "_dns"):
                with suppress(Exception):
                    obj = getattr(helpers, attr, None)
                    if obj is not None:
                        if hasattr(obj, "shutdown"):
                            obj.shutdown()
                        setattr(helpers, attr, None)
            with suppress(Exception):
                pool = getattr(helpers, "process_pool", None)
                if pool is not None:
                    pool.shutdown(wait=False, cancel_futures=True)

    try:
        future = asyncio.run_coroutine_threadsafe(_stop_all(), loop)
        future.result(timeout=timeout)
    except Exception:
        pass

    with suppress(Exception):
        loop.call_soon_threadsafe(loop.stop)
    thread = _SCAN_LOOP_THREAD
    if thread is not None:
        thread.join(timeout=3.0)
    _SCAN_LOOP = None
    _SCAN_LOOP_THREAD = None
