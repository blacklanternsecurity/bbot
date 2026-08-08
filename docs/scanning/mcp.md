# MCP Server

BBOT ships an [MCP](https://modelcontextprotocol.io) server that presents BBOT to an AI agent as a collection of tools rather than as one program with a hundred options.

That is not a disguise. BBOT already is many tools rolled into one: a scan is a module set fed into a recursive engine, and which modules you switch on is what decides whether you are enumerating subdomains or hunting for exposed buckets. The server takes each useful module set, gives it a name an agent can reason about, and exposes it as its own tool.

## Installation

```bash
pip install bbot[mcp]
```

Then register it with your MCP client. For Claude Code:

```bash
claude mcp add bbot -- bbot-mcp
```

For clients configured by file, the server speaks stdio:

```json
{
  "mcpServers": {
    "bbot": {
      "command": "bbot-mcp"
    }
  }
}
```

## Pseudotools

Each tool is defined by one file in `bbot/mcp/capabilities/`. That file **is a BBOT preset** -- runnable with `bbot -p` exactly as it sits -- carrying one extra `meta:` block that the scanner ignores and the MCP server reads.

<!-- BBOT MCP CAPABILITIES -->
| Tool                 | Interaction   | Noise   | Modules   | What it does                                                                                    |
|----------------------|---------------|---------|-----------|-------------------------------------------------------------------------------------------------|
| find_subdomains_deep | mixed         | loud    | 47        | Find an organization's subdomains exhaustively, adding recursive DNS brute-force and mutations. |
| find_subdomains_fast | mixed         | loud    | 45        | Find an organization's subdomains from third-party data, without brute-forcing DNS.             |
<!-- END BBOT MCP CAPABILITIES -->

Three things come from the file itself:

- **the filename** is the tool name, so it has to read like one: `verb_noun`, optionally qualified (`find_subdomains_deep`)
- **`description:`** is the short line. It is the tool's description, resident in the agent's context for the whole session, so it is kept to one sentence
- **`meta:`** is everything else, fetched on demand through `describe_tool`

Everything describing *behavior* is derived by baking the preset: the exact modules it enables, the event types it produces, whether it needs API keys, whether it touches the target, how noisy it is. None of that is written by hand, so it cannot drift when a module changes flags or a bundled preset gains a module.

## Two tiers of prose

The split exists because of what context costs. Every tool's short description is paid for on every single request; the long version is paid for once, and only for a tool the agent has decided to use.

| | Where it lives | When it's read |
|---|---|---|
| **Short** | the preset's `description:` | always resident |
| **Long** | the `meta:` block | on `describe_tool`, once |

The long version is where the operational knowledge goes. Only `when_not_to_use` is required: `description` already says what a tool finds, and this is the one section that can talk an agent out of a tool it has *already chosen*.

The rest are optional. Write the ones that earn their place for a given tool rather than filling in a form:

| Section | Write it when |
|---|---|
| `how_to_call` | scope semantics or a knob will surprise the caller |
| `when_to_use` | there is a situation the one-line `description` cannot convey |
| `how_it_works` | the mechanism is surprising. `describe_tool` already prints the derived module list |
| `interpreting_results` | the output needs reading carefully. Returned **with the results**, not just here |
| `caveats` | there are prerequisites or blind spots |

`how_to_call` is the one that earns its keep. It is where the scope semantics get spelled out -- that BBOT treats everything under a target as in-scope by default, so scanning `evilcorp.com` also covers every host beneath it, and that `strict_scope=True` holds the scan to the exact names you gave. An agent that has not read that will scan more than it meant to.

Tools that set `force_require_tool` are refused until `describe_tool` has been called for them. That is opt-in rather than universal, and only the tools whose blast radius is not in the request set it -- `waf_bypass` probing addresses around every IP it discovers, `find_leaked_secrets` cloning repositories to local disk. There the caveat is the difference between authorized and not, and nothing in the call can be validated against it.

Gating everything instead teaches an agent that the short line is not worth reading, and it stops reaching for tools at all. The one-line descriptions ship in the tool list and are enough to pick from.

## What a scan returns

A pseudotool declares which event types its results are made of:

```yaml
meta:
  yields:
    - DNS_NAME
```

That does two things. The scan collects only those types, so a subdomain tool's results are subdomains rather than every event BBOT emitted on the way there. And each type is rendered by its own renderer in `bbot/mcp/events.py`, because a BBOT event is a graph node rather than a row: a `DNS_NAME` is a bare hostname, a `FINDING` is a dict with a severity and a description, a `STORAGE_BUCKET` is only interesting once you know whether it is readable.

So a subdomain tool returns this:

```
DNS_NAME:
  mail.evilcorp.com
  vpn.evilcorp.com
  staging.evilcorp.com
```

rather than three JSON objects wrapping three strings. Anything without a dedicated renderer falls back to a generic one instead of being dropped.

`yields` is checked against what the preset's modules actually produce, so a tool cannot promise an event type it will never emit -- which would return an empty result set that reads exactly like a clean target.

## Running scans

Scans are asynchronous. A tool returns a `scan_id` immediately and the scan keeps running, because a worthwhile BBOT scan takes tens of minutes to hours and BBOT saves its best findings for late, once early discovery feeds the rest of the modules.

For the agent-facing side of this -- how to select a tool, page through results, and tell an empty result from a clean target -- see [Operating BBOT via MCP](mcp_agent_guide.md).

| Tool | What it does |
|------|--------------|
| *(one per preset file)* | Start a scan against targets. Returns a `scan_id` |
| `list_tools` | The whole menu in one call: what each tool does, and how it behaves |
| `describe_tool` | The long version for one tool. Required only by tools that set `force_require_tool` |
| `scan_status` | Progress, event counts by type, and which modules are busy |
| `scan_results` | Results found so far, readable while the scan is still running |
| `scan_stop` | Abandon a scan, keeping everything it found |

The execution model:

- **In-process, not shelled out.** `Scanner` yields live event objects, which is the only way to read partial results mid-scan.
- **A dedicated event loop on its own thread.** BBOT has synchronous stretches that would otherwise occupy the MCP server's request loop and stall every other tool call.
- **Live accumulators.** Results are readable through `scan_results` while the scan runs, and a scan that is stopped or times out still hands back everything it found.
- **One scan at a time.** A `Scanner` reaches shared DNS caches, the shared resolver, `~/.bbot` state and the dependency installer's lock, so two live scans in one process can wedge each other. A second scan queues; a fourth is refused.

Three behaviors are easy to get wrong and are handled explicitly:

- The event cap bounds what is **returned**, never how long the scan runs. BBOT front-loads bulk discovery and produces its conclusions late, so high-signal types are kept past the cap.
- A scan whose event stream ends is **not** stopped. A scan's status only moves forward and `ABORTED` outranks `FINISHED`, so calling `async_stop()` on a scan that ended by itself rewrites a success into a failure.
- BBOT withholds some event types from output by default (`omit_event_types`). The modules that produce them still run and still feed everything downstream, they are simply never handed to an output module, and `Scanner.async_start()` is one.

## Writing a pseudotool

Create `bbot/mcp/capabilities/<verb>_<noun>.yml`. It is a normal preset plus `meta:`:

```yaml
description: One line. This is the tool description, so keep it short.

include:
  - subdomain-enum
exclude_modules:
  - dnsbrute

meta:
  yields:
    - DNS_NAME
  when_not_to_use: |
    The only required section. When is this the wrong choice, and what instead?
  how_to_call: |
    Optional. Scope, knobs, and the things that surprise people.
```

`description`, `when_not_to_use` and `yields` are required; everything else is optional. Empty prose and leftover `TODO` markers are rejected at load time, so a half-written tool fails the test suite rather than reaching an agent.

`python -m bbot.mcp.scaffold <name> --include <preset>` prints a draft with every derived fact filled in as comments and the prose left as `TODO`. It writes nothing.

The preset body may not set targets (those come from the caller), or `conditions`, `scan_name`, `output_dir`, `module_dirs` or the verbosity flags -- none of which have a CLI-flag equivalent, which would make the emitted command an incomplete representation of what ran.
