"""
The BBOT MCP server.

BBOT is one program that behaves like many, because a scan is just a module set
fed into a recursive engine. This server presents each useful module set as its
own tool, generated from the preset files in `capabilities/`, so an agent sees
`find_subdomains_fast` rather than one generic scanner with a menu of options.

Scans run in-process and in the background; see `bbot.mcp.run` for why.
"""

import inspect
import json
import logging
from typing import Annotated, Optional

from pydantic import Field

from bbot.mcp import events as event_render
from bbot.mcp import format as fmt
from bbot.mcp import run as runner
from bbot.mcp.cli import preset_to_cli
from bbot.mcp.compose import ComposeError, prepare
from bbot.mcp.registry import get_registry

log = logging.getLogger("bbot.mcp.server")

INSTRUCTIONS = """
BBOT is a recursive attack-surface scanner. Each tool here is one BBOT scan
configuration: give it targets and it runs until nothing new is discovered.

`list_tools` shows the whole menu at once. Before running one, call
`describe_tool` on it. The tool's own description says
what it does; `describe_tool` says what it will miss, when it is the wrong choice,
and how to read what comes back. Running is refused until you have.

Scans run in the background and return a scan_id immediately, so start one and
carry on. A worthwhile scan takes tens of minutes to hours, and BBOT saves its
best findings for late, once early discovery feeds the rest of the modules. Read
partial results with `scan_results` while it runs rather than waiting. One scan
runs at a time; a second one queues.

Every scan touches real infrastructure that someone owns. Only run targets the
user is authorized to scan.
""".strip()

BLACKLIST_FIELD = Field(description="Hosts or ranges never to touch. Takes precedence over scope.")
STRICT_SCOPE_FIELD = Field(
    description="Scan only the exact targets given. By default BBOT also treats their subdomains as "
    "in-scope, so scanning evilcorp.com pulls in everything under it."
)


def create_server():
    from mcp.server.fastmcp import FastMCP

    registry = get_registry()
    mcp = FastMCP("bbot", instructions=INSTRUCTIONS)

    def tool(fn):
        """Register a tool, stripping the docstring's indentation.

        FastMCP hands `__doc__` through verbatim, so a nested docstring would
        ship its leading whitespace in the schema and be paid for on every
        request. The generated tools set `__doc__` directly and don't need this.
        """
        fn.__doc__ = inspect.cleandoc(fn.__doc__ or "")
        return mcp.tool()(fn)

    # Tools whose long description has been read this session. A scan is refused
    # until then, so it can never be launched off the short line alone.
    described = set()

    def register(entry):
        """Turn one capability preset into an MCP tool."""

        targets_field = Field(description=fmt.targets_description(entry))

        def run_capability(
            targets: Annotated[list[str], targets_field],
            blacklist: Annotated[Optional[list[str]], BLACKLIST_FIELD] = None,
            strict_scope: Annotated[bool, STRICT_SCOPE_FIELD] = False,
        ) -> str:
            if entry.name not in described:
                return (
                    f"Call describe_tool('{entry.name}') before running it. Its description says what it "
                    "does; the details say what it will miss, when it is the wrong choice, and how to "
                    "read its output."
                )
            try:
                targets, blacklist, warnings = prepare(entry, targets, blacklist)
            except ComposeError as e:
                return f"Could not start this scan: {e}"

            preset_dict = entry.capability.preset.to_preset_dict()
            scan_kwargs = runner.scanner_kwargs(preset_dict, blacklist=blacklist, strict_scope=strict_scope)
            try:
                handle = runner.launch(
                    targets,
                    scan_kwargs,
                    entry.name,
                    runner.DEFAULT_MAX_EVENTS,
                    list(entry.capability.yields),
                    runner.DEFAULT_TIMEOUT_SECONDS,
                    conflicts=warnings,
                )
            except RuntimeError as e:
                return str(e)

            payload = {
                "ok": True,
                "scan_id": handle.scan_id,
                "state": handle.state,
                "targets": targets,
                "tool": entry.name,
                "scan_modules": len(entry.facts.modules),
                "interaction": entry.facts.interaction,
                "noise": entry.facts.noise,
                "yields": list(entry.capability.yields),
                "scope": "exact targets only" if strict_scope else "targets and their subdomains",
                "equivalent_command": preset_to_cli(
                    {**preset_dict, **({"config": scan_kwargs["config"]} if scan_kwargs.get("config") else {})},
                    targets,
                    blacklist,
                ),
                "note": (
                    f"Queued behind {', '.join(handle.queued_behind)}: BBOT runs one scan at a time and "
                    "this one starts when that finishes. You do not need to wait for either."
                    if handle.queued_behind
                    else "Running in the background. Carry on with other work rather than waiting. Check on "
                    f"it with scan_status('{handle.scan_id}') and read what it has found with "
                    f"scan_results('{handle.scan_id}'); both work while it runs."
                ),
            }
            if handle.queued_behind:
                payload["queued_behind"] = handle.queued_behind
            if warnings:
                payload["warnings"] = warnings
            return json.dumps(payload, indent=2, default=str)

        run_capability.__name__ = entry.name
        run_capability.__doc__ = fmt.tool_description(entry)
        mcp.tool()(run_capability)

    for entry in registry.sorted():
        register(entry)

    @tool
    def list_tools() -> str:
        """Every scan tool this server offers, with what each one does.

        One row per tool: what it finds, whether it contacts the target, how
        noisy it is, and how many BBOT modules it runs. This is the whole menu,
        so there is nothing to search for.

        Use it to choose. Then call `describe_tool` on whichever you picked for
        the detail that decides whether running it is actually appropriate.
        """
        return fmt.capabilities_table(registry.sorted())

    @tool
    def describe_tool(
        name: Annotated[str, Field(description="The name of one of this server's scan tools.")],
    ) -> str:
        """Read the full description of a scan tool. Required before running it.

        A tool's own description says what it finds. This says what it will miss,
        when it is the wrong choice and what to use instead, how to read its
        output and what that output does not prove, its caveats and prerequisites,
        the exact BBOT modules it enables, and the preset it runs.

        The short description cannot carry any of that, and those are the things
        that decide whether running a scan against someone's infrastructure is
        appropriate. Scan tools refuse until this has been called for them.
        """
        try:
            entry = registry.get(name)
        except KeyError as e:
            return str(e.args[0])
        described.add(entry.name)
        return fmt.tool_details(entry)

    @tool
    def scan_status(
        scan_id: Annotated[
            str, Field(description="Scan to report on. Omit to report every scan started this session.")
        ] = "",
    ) -> str:
        """Progress of a running scan, or of every scan when called with no id.

        Reports state (running / queued / finished / timed_out / stopped / failed),
        elapsed time, how many events of each type have been seen, and which modules
        are busy. A scan whose counts are still climbing is working, not stuck.

        `scan_status` in the reply is BBOT's own status, which only moves forward:
        STARTING to RUNNING to FINISHING to FINISHED, with ABORTED or FAILED for a
        scan that did not get there. FINISHING is real work, not shutdown: BBOT
        reruns every module's finishing stage and events still arrive during it.
        """
        if scan_id.strip():
            try:
                return json.dumps(runner.get_handle(scan_id).progress(), indent=2, default=str)
            except KeyError as e:
                return str(e.args[0])
        return json.dumps(
            {
                "scans": [handle.progress() for handle in runner.SCANS.values()],
                "running": sum(1 for handle in runner.SCANS.values() if handle.running),
            },
            indent=2,
            default=str,
        )

    @tool
    def scan_results(
        scan_id: Annotated[str, Field(description="Scan to read events from.")],
        since: Annotated[
            int,
            Field(description="Index into the events already returned. Pass back the previous next_since.", ge=0),
        ] = 0,
        limit: Annotated[int, Field(description="Maximum events to return in this page.", ge=1)] = 500,
    ) -> str:
        """Events a scan has found, readable while it is still running.

        These are real results the moment they appear, so act on them rather than
        waiting for the scan to end. Pass back `next_since` from the previous call
        to read only what is new.

        Each event carries its `type`, the `host` it belongs to, the `module` that
        found it, its `scope` (in-scope / affiliate / distance-N) and BBOT's `tags`.
        High-signal events also carry `why`: BBOT's own sentence describing how it
        was discovered, which is usually what tells you whether it is worth chasing.

        The reply also carries the tool's own guidance on reading its output.
        """
        try:
            handle = runner.get_handle(scan_id)
        except KeyError as e:
            return str(e.args[0])
        start = max(0, int(since))
        window = handle.events[start : start + max(1, int(limit))]
        payload = {
            "scan_id": handle.scan_id,
            "tool": handle.selection,
            "state": handle.state,
            "elapsed_seconds": round(handle.elapsed, 1),
            "events_available": len(handle.events),
            "returned": len(window),
            "next_since": start + len(window),
            "more": start + len(window) < len(handle.events),
            # Rendered per event type rather than as raw event objects: a
            # subdomain scan's result is a list of hostnames, and wrapping each
            # one in JSON scaffolding would bury it.
            "results": event_render.render(window),
        }
        if handle.running:
            payload["note"] = "still running -- call again later for events found after this point"
        if handle.result:
            payload["summary"] = handle.result
        if handle.error:
            payload["error"] = handle.error
        # The prose about what results mean is worth far more here than in a tool
        # description, and costs nothing until a scan has actually produced something.
        entry = registry.entries.get(handle.selection)
        if entry is not None and start == 0:
            guidance = {}
            if entry.capability.interpreting_results:
                guidance["interpreting_results"] = entry.capability.interpreting_results
            if entry.capability.caveats:
                guidance["caveats"] = entry.capability.caveats
            if guidance:
                payload["guidance"] = guidance
        return fmt.truncate(
            json.dumps(payload, indent=2, default=str),
            fmt.MAX_RESULTS_CHARS,
            "lower `limit` or page with `since`",
        )

    @tool
    async def scan_stop(
        scan_id: Annotated[str, Field(description="Scan to abandon.")],
    ) -> str:
        """Abandon a running scan, keeping everything it has found so far.

        Use this to free a queue slot or to stop a scan that has already produced
        what was needed. Nothing already discovered is discarded, and the events
        stay readable with `scan_results` afterwards.

        Consider reading `scan_status` first: a scan whose module queues look empty
        is often in its finishing stage, which is where a lot of the best events
        come from.
        """
        try:
            handle = runner.get_handle(scan_id)
        except KeyError as e:
            return str(e.args[0])
        await runner.request_stop(handle)
        return json.dumps(handle.progress(), indent=2, default=str)

    return mcp


def main():
    logging.basicConfig(level=logging.WARNING)
    server = create_server()
    # derive everything up front so the first request doesn't pay for the registry
    get_registry().warm()
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
