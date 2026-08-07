import asyncio
import json

import pytest

from ..bbot_fixtures import *  # noqa F401

from bbot.mcp import events as event_render
from bbot.mcp import run as runner


class _SampleEvent:
    def __init__(self, type, data, host=None, module="testmodule", context="", scope="in-scope", path=None):
        self.type = type
        self.data = data
        self.host = host
        self.module = module
        self.scope_description = scope
        self.discovery_path = path or ([context] if context else [])
        self.parent_chain = ["uuid-root", "uuid-self"] if path else []
        self.tags = ["test"]
        self.discovery_context = context


class _FakeScanner:
    """Streams a fixed event list, standing in for a BBOT scan's event stream."""

    def __init__(self, events, status="FINISHED"):
        self._events = events
        self.status = status
        self.modules = {}
        self.stopped = False

    async def async_start(self):
        for event in self._events:
            yield event

    async def async_stop(self):
        self.stopped = True


@pytest.fixture(autouse=True)
def clean_scan_registry():
    """Scans live in module-level state, so each test starts and leaves it empty."""
    runner.SCANS.clear()
    runner._SCAN_TASKS.clear()
    yield
    runner.SCANS.clear()
    runner._SCAN_TASKS.clear()


def _collect(events, max_events, event_types=None, status="FINISHED"):
    counts, collected = {}, []
    scanner = _FakeScanner(events, status=status)
    asyncio.run(runner.collect_events(scanner, max_events, event_types or [], counts, collected))
    return scanner, counts, collected


def test_event_cap_bounds_results_not_the_scan():
    """BBOT front-loads bulk discovery and produces its best events late, so a cap
    reached early must not cost the findings that arrive afterwards."""
    bulk = [_SampleEvent("DNS_NAME", f"h{i}.evilcorp.com", host=f"h{i}.evilcorp.com") for i in range(50)]
    late = [
        _SampleEvent("FINDING", {"description": "exposed .git"}, host="evilcorp.com"),
        _SampleEvent("TECHNOLOGY", "nginx", host="evilcorp.com"),
    ]
    _, counts, collected = _collect(bulk + late, max_events=10)

    assert counts["DNS_NAME"] == 50, "the scan must drain fully regardless of the cap"
    types = [event["type"] for event in collected]
    assert types.count("DNS_NAME") == 10, "bulk events stop at the cap"
    assert "FINDING" in types and "TECHNOLOGY" in types, "high-signal events survive past the cap"


def test_out_of_scope_events_are_dropped():
    """A subdomain scan emits the target's nameservers, its mail exchangers and
    affiliates found in certificates. Those are real, and they are not the
    answer to the question the tool was asked."""
    events = [
        _SampleEvent("DNS_NAME", "real.evilcorp.com", host="real.evilcorp.com"),
        _SampleEvent("DNS_NAME", "aspmx.l.google.com", host="aspmx.l.google.com", scope="affiliate"),
        _SampleEvent("DNS_NAME", "ns1.example.net", host="ns1.example.net", scope="distance-1"),
    ]
    _, counts, collected = _collect(events, max_events=100)
    assert counts["DNS_NAME"] == 3, "everything is still counted; only what is returned is filtered"
    assert [e["data"] for e in collected] == ["real.evilcorp.com"]


def test_event_type_filter_narrows_results():
    events = [
        _SampleEvent("DNS_NAME", "a.evilcorp.com", host="a.evilcorp.com"),
        _SampleEvent("URL", "https://evilcorp.com/", host="evilcorp.com"),
    ]
    _, counts, collected = _collect(events, max_events=100, event_types=["URL"])
    assert counts["DNS_NAME"] == 1, "filtering changes what is returned, not what is counted"
    assert [event["type"] for event in collected] == ["URL"]


def test_finished_scan_is_not_stopped_into_aborted():
    """A scan's status only moves forward and ABORTED outranks FINISHED, so calling
    stop on a scan that ended by itself would rewrite a success into a failure."""
    scanner, _, _ = _collect([], max_events=10, status="FINISHED")
    assert scanner.stopped is False


def test_scan_still_running_when_the_stream_ends_is_stopped():
    scanner, _, _ = _collect([], max_events=10, status="RUNNING")
    assert scanner.stopped is True


def test_the_chain_and_raw_record_are_opt_in():
    """Both are held in memory and neither is returned unless asked for: most
    reads of a result list need neither, and they are not cheap."""
    chain = ["seeded with evilcorp.com", "excavate found GETPARAM id", "lightfuzz fuzzed it"]
    record = runner.event_record(
        _SampleEvent("FINDING", {"description": "SQLi"}, host="app.evilcorp.com", context=chain[-1], path=chain)
    )
    assert "_full" not in event_render.render([record])["FINDING"]

    default = event_render.render([record])["FINDING"]
    assert "how it was reached" not in default
    assert chain[0] not in default, "the chain must not leak into the default view"
    assert "via: lightfuzz fuzzed it" in default, "the last step alone is cheap and still worth showing"

    detailed = event_render.render([record], detail=True)["FINDING"]
    assert "how it was reached" in detailed
    assert all(step in detailed for step in chain)
    assert len(detailed) > len(default)


def test_full_records_returns_the_raw_bbot_event():
    class _WithJson(_SampleEvent):
        def json(self):
            return {"type": "FINDING", "id": "FINDING:abc", "uuid": "u-1", "scope_distance": 0}

    record = runner.event_record(_WithJson("FINDING", {"description": "x"}, host="h", path=["a"]))
    assert event_render.has_full_records([record])
    raw = event_render.full_records([record])[0]
    assert raw["id"] == "FINDING:abc", "the raw record is BBOT's own, not our summary"

    # a bulk event has no raw record, and must still come back rather than vanish
    bulk = runner.event_record(_SampleEvent("DNS_NAME", "a.evilcorp.com", host="a.evilcorp.com"))
    assert not event_render.has_full_records([bulk])
    assert event_render.full_records([bulk])[0]["data"] == "a.evilcorp.com"


def test_findings_carry_their_full_discovery_chain():
    """`discovery_path` is what output.json carries: every step from the scan's
    seed to this event. For a finding it is the difference between 'there is a
    bug here' and 'here is the route that reached it'."""
    chain = [
        "Scan seeded with evilcorp.com",
        "crt found DNS_NAME: app.evilcorp.com",
        "excavate found GETPARAM id",
        "lightfuzz fuzzed GETPARAM id",
    ]
    record = runner.event_record(
        _SampleEvent("FINDING", {"description": "SQLi"}, host="app.evilcorp.com", context=chain[-1], path=chain)
    )
    assert record["discovery_path"] == chain
    # the ids that tie a finding back to the scan's own output.json live in the
    # raw record, which `full_records=True` returns
    assert "_full" not in event_render.render([record], detail=True)["FINDING"]

    rendered = event_render.render([record], detail=True)["FINDING"]
    assert "how it was reached:" in rendered
    for step in chain:
        assert step in rendered
    # the chain already ends with `why`, so it is not printed twice
    assert "via:" not in rendered


def test_bulk_events_do_not_carry_the_chain():
    """On a flood of DNS_NAMEs the chain costs far more than it says."""
    record = runner.event_record(
        _SampleEvent("DNS_NAME", "a.evilcorp.com", host="a.evilcorp.com", path=["seeded", "crt found it"])
    )
    assert "discovery_path" not in record
    assert "why" not in record


def test_event_record_carries_why_only_on_high_signal():
    finding = runner.event_record(
        _SampleEvent("FINDING", {"description": "x"}, host="evilcorp.com", context="excavate found it in a JS file")
    )
    assert finding["why"] == "excavate found it in a JS file"
    assert finding["scope"] == "in-scope"

    bulk = runner.event_record(_SampleEvent("DNS_NAME", "a.evilcorp.com", host="a.evilcorp.com", context="dns brute"))
    assert "why" not in bulk, "the context sentence costs more than it says on a flood of DNS_NAMEs"


def test_event_record_handles_non_json_data():
    record = runner.event_record(_SampleEvent("DNS_NAME", object()))
    assert isinstance(record["data"], str)


def test_module_activity_summarizes_busy_queues():
    class _Module:
        def __init__(self, incoming, outgoing, tasks=0, errored=False):
            self.status = {"events": {"incoming": incoming, "outgoing": outgoing}, "tasks": tasks, "errored": errored}

    scanner = _FakeScanner([])
    scanner.modules = {
        "idle": _Module(0, 0),
        "busy": _Module(5, 2),
        "broken": _Module(0, 0, errored=True),
    }
    activity = runner.module_activity(scanner)
    assert "busy(5->2)" in activity
    assert "idle" not in activity
    assert "errored: broken" in activity


def test_module_activity_is_safe_without_a_scanner():
    assert runner.module_activity(None) == ""
    assert runner.module_activity(_FakeScanner([])) == ""


def test_scanner_kwargs_resolves_includes_to_shipped_presets():
    """The scan has to run the configuration that was advertised, so `include:`
    must not go through the global preset search path."""
    kwargs = runner.scanner_kwargs(
        {"include": ["tech-detect"], "modules": ["portscan"], "config": {"scope": {"strict": True}}},
        blacklist=["prod.evilcorp.com"],
    )
    assert len(kwargs["presets"]) == 1
    assert kwargs["presets"][0].endswith("bbot/presets/tech-detect.yml")
    assert kwargs["modules"] == ["portscan"]
    assert kwargs["config"] == {"scope": {"strict": True}}
    assert kwargs["blacklist"] == ["prod.evilcorp.com"]
    assert "output_dir" not in kwargs


def test_scanner_kwargs_omits_empty_keys():
    assert runner.scanner_kwargs({}) == {}


def test_scan_result_flags_modules_that_did_not_run():
    """A module whose setup fails is dropped and the scan runs without it. Unsaid,
    a scan missing half its enumeration reads like a thorough one that found less."""
    scanner = _FakeScanner([], status="FINISHED")
    scanner.modules = {"http": object()}
    result = runner.scan_result(
        ["evilcorp.com"], scanner, {"URL": 1}, [{"type": "URL"}], requested_modules=["http", "shodan_dns"]
    )
    assert result["modules_unavailable"] == ["shodan_dns"]
    assert result["scan_status"] == "FINISHED"


def test_scan_result_reports_truncation():
    scanner = _FakeScanner([], status="FINISHED")
    result = runner.scan_result(["evilcorp.com"], scanner, {"DNS_NAME": 100}, [{"type": "DNS_NAME"}])
    assert result["truncated"] is True


async def test_timed_out_scan_returns_what_it_found(monkeypatch):
    """Everything found before the cutoff is real and already paid for; returning
    an error instead would discard it."""

    class _Endless(_FakeScanner):
        async def async_start(self):
            yield _SampleEvent("DNS_NAME", "a.evilcorp.com", host="a.evilcorp.com")
            yield _SampleEvent("FINDING", {"description": "x"}, host="evilcorp.com")
            while True:
                await asyncio.sleep(0.05)

    handle = runner.ScanHandle(scan_id="t", targets=["evilcorp.com"], selection="test", started_at=0.0)
    scanner = _Endless([], status="RUNNING")
    monkeypatch.setattr(runner, "_build_scanner", lambda targets, kwargs: scanner)

    result = await runner.run_scan(["evilcorp.com"], {}, 100, [], timeout=0.3, handle=handle)
    assert result["timed_out"] is True
    assert result["event_count"] == 2, "the events found before the cutoff are kept"
    assert "longer timeout_seconds" in result["note"]
    assert scanner.stopped is True, "an abandoned scan must actually be stopped"


async def test_a_timed_out_scan_that_found_nothing_is_an_error(monkeypatch):
    """Nothing at all in the whole window is a setup failure, not a slow scan."""

    class _Silent(_FakeScanner):
        async def async_start(self):
            while True:
                await asyncio.sleep(0.05)
            yield  # pragma: no cover

    monkeypatch.setattr(runner, "_build_scanner", lambda targets, kwargs: _Silent([], status="RUNNING"))
    with pytest.raises(ValueError, match="produced nothing"):
        await runner.run_scan(["evilcorp.com"], {}, 10, [], timeout=0.2)


async def test_run_scan_requires_a_target():
    with pytest.raises(ValueError, match="at least one target"):
        await runner.run_scan([], {}, 10, [], 1.0)


def test_unknown_scan_id_says_which_exist():
    with pytest.raises(KeyError, match="none"):
        runner.get_handle("nope")


def test_scan_handle_progress_distinguishes_queued_from_working():
    handle = runner.ScanHandle(
        scan_id="q", targets=["evilcorp.com"], selection="test", started_at=0.0, state="queued", queued_at=0.0
    )
    report = handle.progress()
    assert report["state"] == "queued"
    assert "one scan at a time" in report["note"]

    handle.state = "running"
    handle.scanner = _FakeScanner([], status="FINISHING")
    report = handle.progress()
    assert report["scan_status"] == "FINISHING"
    # empty queues are not the same as finished: BBOT's finishing stage still works
    assert "finishing stage" in report["note"]


async def test_scan_runs_in_the_background_while_results_are_readable(monkeypatch):
    """Launching must not block, and what it finds must be usable before it ends."""

    class _Streaming(_FakeScanner):
        async def async_start(self):
            for event in self._events:
                await asyncio.sleep(0.01)
                yield event

    events = [_SampleEvent("DNS_NAME", f"h{i}.evilcorp.com", host=f"h{i}.evilcorp.com") for i in range(20)]
    events.append(_SampleEvent("FINDING", {"description": "exposed .git"}, host="evilcorp.com"))
    monkeypatch.setattr(runner, "_build_scanner", lambda targets, kwargs: _Streaming(events))

    handle = runner.launch(["evilcorp.com"], {}, "test", 2000, [], 60.0)
    assert handle.state == "running"

    for _ in range(300):
        await asyncio.sleep(0.01)
        if handle.events:
            break
    assert handle.events, "partial results must be readable before the scan ends"

    for _ in range(600):
        await asyncio.sleep(0.01)
        if not handle.running:
            break
    assert handle.state == "finished"
    assert len(handle.events) == 21
    assert handle.result["scan_status"] == "FINISHED"


async def test_a_blocking_scanner_cannot_stall_the_mcp_loop(monkeypatch):
    """Real BBOT has synchronous stretches; they must not occupy the request loop."""
    import time as _time

    class _Blocking(_FakeScanner):
        async def async_start(self):
            _time.sleep(0.5)
            for event in self._events:
                yield event

    monkeypatch.setattr(
        runner, "_build_scanner", lambda targets, kwargs: _Blocking([_SampleEvent("DNS_NAME", "a.evilcorp.com")])
    )
    handle = runner.launch(["evilcorp.com"], {}, "test", 10, [], 60.0)

    start = _time.monotonic()
    await asyncio.sleep(0.05)
    # the MCP loop stayed responsive while the scan thread was blocked
    assert _time.monotonic() - start < 0.4

    for _ in range(600):
        await asyncio.sleep(0.01)
        if not handle.running:
            break
    assert handle.state == "finished"


async def test_a_second_scan_queues_instead_of_running_alongside(monkeypatch):
    """Two live Scanners in one process can wedge each other, so the second waits."""
    running = []

    class _Slow(_FakeScanner):
        async def async_start(self):
            running.append(1)
            try:
                assert len(running) == 1, "two scans ran at the same time"
                for _ in range(20):
                    await asyncio.sleep(0.01)
                yield _SampleEvent("DNS_NAME", "a.evilcorp.com", host="a.evilcorp.com")
            finally:
                running.pop()

    monkeypatch.setattr(runner, "_build_scanner", lambda targets, kwargs: _Slow([]))

    first = runner.launch(["evilcorp.com"], {}, "first", 10, [], 60.0)
    second = runner.launch(["evilcorp.org"], {}, "second", 10, [], 60.0)
    assert second.state == "queued"
    assert second.progress()["note"].startswith("waiting for the running scan")

    for _ in range(800):
        await asyncio.sleep(0.01)
        if not first.running and not second.running:
            break
    assert first.state == "finished"
    assert second.state == "finished"


async def test_the_scan_queue_is_bounded(monkeypatch):
    class _Slow(_FakeScanner):
        async def async_start(self):
            for _ in range(50):
                await asyncio.sleep(0.01)
            yield _SampleEvent("DNS_NAME", "a.evilcorp.com", host="a.evilcorp.com")

    monkeypatch.setattr(runner, "_build_scanner", lambda targets, kwargs: _Slow([]))
    handles = [runner.launch(["evilcorp.com"], {}, f"s{i}", 10, [], 60.0) for i in range(runner.MAX_ACTIVE_SCANS)]
    with pytest.raises(RuntimeError, match="queue is full"):
        runner.launch(["evilcorp.com"], {}, "overflow", 10, [], 60.0)

    for handle in handles:
        await runner.request_stop(handle)


async def test_stopping_keeps_what_was_found(monkeypatch):
    class _Endless(_FakeScanner):
        async def async_start(self):
            yield _SampleEvent("DNS_NAME", "a.evilcorp.com", host="a.evilcorp.com")
            while True:
                await asyncio.sleep(0.05)

    monkeypatch.setattr(runner, "_build_scanner", lambda targets, kwargs: _Endless([], status="RUNNING"))
    handle = runner.launch(["evilcorp.com"], {}, "test", 10, [], 60.0)
    for _ in range(300):
        await asyncio.sleep(0.01)
        if handle.events:
            break

    await runner.request_stop(handle)
    assert handle.state in ("stopped", "stopping")
    assert len(handle.events) == 1, "everything found before the stop is kept"


def test_default_omitted_types_reads_the_live_config():
    """Read from BBOT rather than a hardcoded list, so it tracks the build.

    The test config sets `omit_event_types: []` (bbot/test/test.conf), so the
    value here is empty under pytest and non-empty in production. Assert it
    matches the config either way rather than asserting a particular list."""
    from bbot.scanner import Preset

    expected = sorted(str(t) for t in (Preset(_log=False).core.default_config.get("omit_event_types") or []))
    assert runner.default_omitted_types() == expected


def test_omission_note_warns_about_types_bbot_withholds(monkeypatch):
    """Asking for a type BBOT omits yields an empty scan that reads like a clean
    target, so it has to be called out at launch."""
    monkeypatch.setattr(runner, "default_omitted_types", lambda: ["HTTP_RESPONSE", "URL_UNVERIFIED"])

    note = runner.omission_note(["URL_UNVERIFIED"], {})
    assert "URL_UNVERIFIED" in note
    assert "omit_event_types" in note
    assert "HTTP_RESPONSE" in note, "the note should name everything this build omits"

    # a caller who set the list already knows
    assert runner.omission_note(["URL_UNVERIFIED"], {"omit_event_types": []}) == ""
    # a type that is not omitted needs no warning
    assert runner.omission_note(["DNS_NAME"], {}) == ""
    assert runner.omission_note([], {}) == ""


async def test_scan_tools_report_progress_and_results(monkeypatch):
    """The four execution tools, driven the way an agent would drive them."""
    pytest.importorskip("mcp")
    from bbot.mcp.server import create_server

    class _Streaming(_FakeScanner):
        async def async_start(self):
            for event in self._events:
                await asyncio.sleep(0.01)
                yield event

    events = [_SampleEvent("DNS_NAME", f"h{i}.evilcorp.com", host=f"h{i}.evilcorp.com") for i in range(5)]
    monkeypatch.setattr(runner, "_build_scanner", lambda targets, kwargs: _Streaming(events))

    server = create_server()

    async def call(tool, **kwargs):
        result = await server.call_tool(tool, kwargs)
        content = result[0] if isinstance(result, tuple) else result
        return "".join(block.text for block in content)

    await call("describe_tool", name="find_subdomains_fast")
    launched = json.loads(await call("find_subdomains_fast", targets=["evilcorp.com"]))
    assert launched["ok"] is True
    assert launched["interaction"] == "mixed"
    scan_id = launched["scan_id"]

    for _ in range(600):
        await asyncio.sleep(0.01)
        if json.loads(await call("scan_status", scan_id=scan_id))["state"] != "running":
            break

    results = json.loads(await call("scan_results", scan_id=scan_id))
    assert results["state"] == "finished"
    assert results["events_available"] == 5
    assert "DNS_NAME" in results["results"]
    assert results["summary"]["scan_status"] == "FINISHED"

    # every scan, with no id
    assert json.loads(await call("scan_status"))["scans"]

    assert "unknown scan_id" in await call("scan_results", scan_id="nope")
    assert "unknown scan_id" in await call("scan_stop", scan_id="nope")


async def test_scan_tool_rejects_bad_targets_before_launching():
    pytest.importorskip("mcp")
    from bbot.mcp.server import create_server

    server = create_server()

    async def call(tool, **kwargs):
        result = await server.call_tool(tool, kwargs)
        content = result[0] if isinstance(result, tuple) else result
        return "".join(block.text for block in content)

    await call("describe_tool", name="find_subdomains_fast")
    assert "Could not start this scan" in await call("find_subdomains_fast", targets=["README.md"])
    assert not runner.SCANS, "a rejected request must not consume a queue slot"
