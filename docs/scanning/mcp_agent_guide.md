# Operating BBOT via MCP

Guidance for an AI agent driving the [MCP server](mcp.md). The server ships a short version of this in its own instructions; this is the long form, covering what agents get wrong that the tool schemas do not say.

## Selection

Every tool's one-line description is already in the tool list. That is what it finds, and it is enough to pick from. `list_tools` puts those lines side by side for comparing the menu at once; it is not where descriptions come from, and nothing has to be called to learn what a tool does.

`describe_tool` goes further: what a scan will miss, when it is the wrong choice and what to use instead, how to read its output and what that output does not prove, its caveats and prerequisites, the modules it enables, and the preset it runs. Call it before a scan that is slow, noisy, or aimed at infrastructure of uncertain ownership, and whenever an empty result needs interpreting.

A few tools refuse to run until it has been called for them. Those are the ones that reach past the targets they are given: `waf_bypass` probes addresses around every IP it discovers, and `find_leaked_secrets` clones repositories to local disk. For those, what will be touched is in the detail rather than in the request, and nothing in the call can be checked against it. They say so when they refuse.

Pick by intent, not by composition. BBOT is recursive: one scan runs until nothing new is discovered. These tools are not pipeline stages and do not chain. If two tools both look relevant, the right move is usually the one whose intent matches, not both.

Do feed results forward as *targets* where a tool says to. `find_subdomains_fast` produces a hostname list, and `baddns` wants exactly that as input. That is not composition, it is giving the next tool better input.

## Launching

A tool call returns a `scan_id` immediately and the scan runs in the background. Read the launch payload before moving on:

- `equivalent_command` is the real `bbot` invocation. Sanity-check it against what was intended.
- `interaction` and `noise` say whether this touches the target, and how loudly.
- `scope` is `targets and their subdomains` by default. When authorization names specific hosts, pass `strict_scope=true`.
- `warnings` names modules that need root and will not get it. Those soft-fail silently, so the scan looks healthy and quietly does less. Fix it at launch or knowingly accept narrower results.
- `queued_behind` means another scan holds the lock. One scan runs at a time and a second one queues; neither needs to be waited on.

Set `blacklist` **before** starting. It takes precedence over scope and is the only reliable way to keep a scan off something. Adding it afterwards does nothing.

Refusals come in two shapes, and they carry different amounts of help. A call that reaches BBOT's target validation -- an empty list, whitespace, a filesystem path, an unparseable host -- comes back as `Could not start this scan:` with the reason and a pointer to `describe_tool`. A call that is malformed at the schema boundary, such as a non-string target or a missing `targets` argument, is rejected by the tool layer before BBOT sees it and carries no pointer; the validation error itself is the whole message.

## While it runs

Do not block and do not busy-poll. Start the scan, do other work, come back.

A worthwhile scan takes tens of minutes to hours. BBOT saves its best findings for late, because early discovery feeds the rest of the modules, so results arrive back-loaded. A scan that looks idle near the end is often doing the thing it was started for. `waf_bypass` in particular does all of its real testing in the scan's finishing stage.

Read partial results as they arrive. They are real results the moment they appear, not provisional ones.

## Reading results

Call `scan_results(scan_id)`, then `scan_results(scan_id, since=<previous next_since>)`. It is cursor paging, and `more` says whether to keep going.

Capture the guidance on the first page. When `since=0`, the reply carries that tool's `interpreting_results` and `caveats`. Page past it and it does not come back. That text is the difference between reading a finding and understanding it, so read it before judging anything.

Detail comes in three tiers, and the default is deliberate:

| tier | what it returns | when to ask for it |
|------|-----------------|--------------------|
| default | compact summary, shaped per event type | scanning the list |
| `detail=true` | adds the full discovery chain per finding | judging or reproducing one result |
| `full_records=true` | raw BBOT events, the same objects as `output.json` | a needed field is missing from the summary |

Do not reach for `full_records` by habit. It is several times the size per event, so page it with a small `limit`.

Read the tags. Provenance tags change what a result means: `used-nowafpls` says a finding only landed because the payload was padded past a WAF and will not reproduce without it. `from-wayback` says it came from the archive and may not exist today.

## An empty result is not a clean target

Several tools silently do nothing:

- `lightfuzz` skips WAF-protected hosts whose WAF is not bypassable.
- `web_brute` skips WAF-protected hosts outright.
- The `iis_shortnames` tools find nothing on anything that is not IIS.
- `port_scan` silently downgrades to a connect scan without root.
- Key-gated modules soft-fail when an API key is missing, and the scan continues.

Before concluding a target is clean, check the scan's `state`, the launch `warnings`, whether the modules being counted on actually ran, and what the tool's own `caveats` say it cannot see. Each tool's `describe_tool` names its specific silent-skip condition, so a quiet scan is one of the moments worth calling it for.

## Stopping

`scan_stop` abandons a scan and keeps everything found so far. Use it once the answer is in hand rather than letting a long scan finish for completeness.

Do not stop a tool early when its `describe_tool` says the work happens at the end.

## Authorization

Every scan touches real infrastructure that someone owns. Only run targets the user is authorized to scan.

Two tools reach further than their target list implies, and both say so. `waf_bypass` probes 256 addresses around every IP it discovers, most of which belong to other tenants on shared hosting. `find_leaked_secrets` clones third-party repositories to local disk, potentially including ones belonging to employees personally. Read those two carefully before running them.
