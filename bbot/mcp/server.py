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

from bbot.mcp import deps
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
            # Modules that escalate at scan time soft-fail without root rather
            # than stopping the scan, so the run looks healthy and quietly does
            # less. Say so at launch, while it can still be fixed.
            rootless = [] if deps.root_available() else deps.modules_needing_root(entry)
            if rootless:
                warnings = list(warnings) + [
                    f"{', '.join(rootless)} may need root and this process cannot obtain it. Those modules "
                    f"will be skipped, so results will be narrower than the tool advertises. Fix with "
                    f"`bbot-mcp --install-deps` from a terminal, or set BBOT_SUDO_PASS."
                ]
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
        detail: Annotated[
            bool,
            Field(
                description="Add the discovery chain to each finding: every step from the scan's seed to "
                "the finding, in order. Costs roughly a paragraph per finding. Ask for it when you need to "
                "judge or reproduce a specific result, not when scanning the list."
            ),
        ] = False,
        full_records: Annotated[
            bool,
            Field(
                description="Return the complete raw BBOT event records instead of the readable summary - "
                "the same objects the scan writes to its output.json, with every field: ids, uuids, "
                "timestamps, parent references, resolved hosts, scope distance, module sequence, host "
                "metadata. Large: several times the size of the summary per event, so page with a small "
                "`limit`. Only high-signal events keep one. Ask for it when you need a field the summary "
                "does not show, or to cross-reference against the scan's own output files."
            ),
        ] = False,
    ) -> str:
        """Events a scan has found, readable while it is still running.

        These are real results the moment they appear, so act on them rather than
        waiting for the scan to end. Pass back `next_since` from the previous call
        to read only what is new.

        Each event carries its `type`, the `host` it belongs to, the `module` that
        found it, its `scope` (in-scope / affiliate / distance-N) and BBOT's `tags`.
        High-signal events also carry `why`: BBOT's own sentence describing how it
        was discovered, which is usually what tells you whether it is worth chasing.

        By default this returns a compact, readable summary shaped for each event
        type. Two things are held back because most reads do not need them and
        they are not cheap: `detail=True` adds each finding's full discovery
        chain, and `full_records=True` returns the complete raw BBOT event
        objects from the scan's output.json. Both are described on those
        parameters.

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
        }
        if full_records:
            payload["records"] = event_render.full_records(window)
        else:
            # Rendered per event type rather than as raw event objects: a
            # subdomain scan's result is a list of hostnames, and wrapping each
            # one in JSON scaffolding would bury it.
            payload["results"] = event_render.render(window, detail=detail)
            if not detail and event_render.has_full_records(window):
                payload["more_detail_available"] = (
                    "Findings here have a full discovery chain and a complete raw record. Neither is "
                    "included by default. Call again with detail=true for the chain that reached each "
                    "finding, or full_records=true for the raw BBOT events."
                )
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

    @tool
    async def scan_forget(
        scan_id: Annotated[str, Field(description="Finished scan whose results you are done with.")],
    ) -> str:
        """Release a finished scan's results, freeing what the server held for it.

        A scan stays readable after it ends, so its events are kept until
        something says they are no longer wanted. Call this once you have read a
        scan and stored what you need: the scan_id stops resolving and the memory
        goes back, which is what lets one server run scans all day.

        This does not stop anything -- a running scan is refused, because ending
        one is `scan_stop`. The server also forgets its oldest finished scans on
        its own once enough pile up, so this is how to be prompt rather than how
        to avoid running out.
        """
        if runner.forget_scan(scan_id):
            return json.dumps({"scan_id": scan_id, "forgotten": True}, indent=2)
        handle = runner.SCANS.get(scan_id)
        if handle is not None and handle.running:
            return json.dumps(
                {
                    "scan_id": scan_id,
                    "forgotten": False,
                    "reason": f"the scan is {handle.state}; end it with scan_stop first",
                },
                indent=2,
            )
        return json.dumps(
            {"scan_id": scan_id, "forgotten": False, "reason": "no such scan; it may already be forgotten"},
            indent=2,
        )

    return mcp


def main():
    import argparse
    import asyncio

    parser = argparse.ArgumentParser(
        prog="bbot-mcp",
        description="Serve BBOT's pseudotools over MCP (stdio).",
    )
    parser.add_argument(
        "--check-deps",
        action="store_true",
        help="report which tools have unmet external dependencies, install nothing, and exit",
    )
    parser.add_argument(
        "--check-keys",
        action="store_true",
        help="report which tools are limited by missing API keys, and where to put them",
    )
    parser.add_argument(
        "--install-deps",
        action="store_true",
        help="install dependencies for the modules the pseudotools use, then exit. Idempotent: "
        "a no-op where they are already present, such as bbot-docker-full",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO if (args.check_deps or args.check_keys or args.install_deps) else logging.WARNING
    )
    # Applied before anything reads config, so a containerised server can be
    # given keys through the MCP client's `env` block instead of a mounted file.
    from_env = deps.apply_env_config()
    if from_env:
        log.info("applied config from environment for: %s", ", ".join(sorted(from_env)))
    registry = get_registry()

    if args.check_deps:
        installable, privileged = deps.report(registry)
        if not installable and not privileged:
            print("All pseudotool dependencies look satisfied.")
            return
        if installable:
            print(f"{len(installable)} module(s) need dependencies installed:\n")
            for module, reasons in sorted(installable.items()):
                print(f"  {module:24} {'; '.join(reasons)}")
            print(
                "\n  Fix: bbot-mcp --install-deps"
                + ("  (run it from a terminal; it will prompt for sudo)" if not deps.root_available() else "")
            )
        if privileged:
            if installable:
                print()
            print(f"{len(privileged)} module(s) are installed but need root to run:\n")
            for module, reasons in sorted(privileged.items()):
                print(f"  {module:24} {'; '.join(reasons)}")
            print("\n  There is nothing to install here, so --install-deps will not help.")
            print("  Fix: set BBOT_SUDO_PASS, configure passwordless sudo, or run the server as root.")
            print("  Otherwise these modules are skipped and the scan quietly does less.")
        return

    if args.check_keys:
        configured, missing = deps.api_key_status(registry)
        if configured:
            print(f"Keys already set for: {', '.join(sorted(configured))}\n")
        if not missing:
            print("Every pseudotool module that takes an API key has one.")
            return
        affected = {}
        for entry in registry:
            hit = sorted(set(entry.facts.modules) & set(missing))
            if hit:
                affected[entry.name] = hit
        # BBOT does not record which keys are mandatory: `options_mandatory` is
        # empty even for modules that soft-fail without one (github_org). So the
        # honest statement is that these take a key, not that they all demand one.
        print(f"{len(missing)} module(s) take an API key and have none set. Some refuse to run")
        print("without one, others just return less; BBOT does not distinguish them.\n")
        for tool, mods in sorted(affected.items(), key=lambda kv: -len(kv[1])):
            shown = ", ".join(mods[:6]) + (f" (+{len(mods) - 6} more)" if len(mods) > 6 else "")
            print(f"  {tool:22} {len(mods):>2} affected: {shown}")
        print(f"\nAdd the ones you have to {deps.secrets_path()}:\n")
        print("modules:")
        for module, options in sorted(missing.items()):
            for option in options:
                print(f'  {module}:\n    {option.rsplit(".", 1)[-1]}: ""')
        print("\nOnly the ones you actually have -- an empty value is the same as unset.")
        return

    if args.install_deps:
        raise SystemExit(0 if asyncio.run(deps.install(registry)) else 1)

    server = create_server()
    # derive everything up front so the first request doesn't pay for the registry
    registry.warm()
    # Never install anything on its own -- just say so once, on stderr, and let
    # the operator decide. An environment that already has the binaries sees
    # nothing.
    installable, privileged = deps.report(registry)
    if installable or privileged:
        log.warning(
            "%d module(s) need dependencies installed, %d need root to run; run `bbot-mcp --check-deps` for detail",
            len(installable),
            len(privileged),
        )
    import atexit
    import sys

    atexit.register(runner.shutdown_scan_loop)
    try:
        server.run(transport="stdio")
    except BaseException as exc:
        print(f"bbot-mcp: server.run exited with {type(exc).__name__}: {exc}", file=sys.stderr)
        raise
    finally:
        runner.shutdown_scan_loop()


if __name__ == "__main__":
    main()
