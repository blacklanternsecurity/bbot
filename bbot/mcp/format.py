"""
Renders capabilities for an agent, in two tiers.

The short tier is a tool's description. Every one of them is resident in the
agent's context for the whole session, so it is kept to the preset's own
`description` line plus a single derived line about how the scan behaves.

The long tier is `describe_tool`'s output: the full prose from the file's `meta:`
block plus everything derived from the preset. It is fetched once, only for a
tool the agent has decided to use, so it can afford to be thorough.
"""

import yaml

from bbot.core.helpers.misc import make_table
from bbot.mcp.derive import INTERNAL_MODULE_NOTE

# Per-response ceilings, enforced by tests so a growing registry cannot quietly
# start flooding the agent's context.
MAX_DESCRIPTION_CHARS = 1200
MAX_DETAILS_CHARS = 8000
MAX_RESULTS_CHARS = 24000


def truncate(text, max_chars, hint):
    if len(text) <= max_chars:
        return text
    return f"{text[:max_chars].rstrip()}\n\n[truncated at {max_chars} chars -- {hint}]"


def _markdown_table(rows, header):
    """Render as a markdown table.

    `make_table` only escapes pipes when the `BBOT_TABLE_FORMAT` env var selects
    a markdown format, and passing `tablefmt` as a kwarg doesn't trigger that
    path. Escaping here keeps a pipe in a description from breaking the table
    without this layer mutating the process environment.
    """
    rows = [[str(cell).replace("|", "&#124;") for cell in row] for row in rows]
    header = [str(h).replace("|", "&#124;") for h in header]
    return make_table(rows, header, tablefmt="github", maxcolwidths=None)


def _prose_section(title, body):
    return f"\n## {title}\n\n{body.strip()}\n" if body and body.strip() else ""


# How to say each target type in a sentence.
ACCEPTS_PHRASING = {
    "DNS_NAME": "domains and hostnames",
    "IP_ADDRESS": "IP addresses",
    "IP_RANGE": "CIDR ranges",
    "URL": "URLs",
    "EMAIL_ADDRESS": "email addresses",
    "OPEN_TCP_PORT": "host:port pairs",
}


def targets_description(entry):
    """The `targets` parameter's description, specific to what this tool is for.

    A subdomain tool takes domains and a fuzzer takes URLs. Pointing either at
    the other's input wastes a whole scan, so the parameter says which it wants
    rather than leaving it to be guessed from the tool's name.
    """
    kinds = [ACCEPTS_PHRASING.get(a, a) for a in entry.capability.accepts]
    if len(kinds) > 1:
        wanted = ", ".join(kinds[:-1]) + f" or {kinds[-1]}"
    else:
        wanted = kinds[0] if kinds else "targets"
    return (
        f"{wanted[0].upper()}{wanted[1:]} to scan. These define the scan's scope. "
        "Pass them literally; file paths are rejected. Put everything you want covered in one call."
    )


def behavior_line(facts):
    """One line naming what the scan will do to the target. Short enough to sit
    in every tool description, and the part an agent needs before it acts."""
    parts = [f"{facts.interaction} against the target", f"{facts.noise} on the wire"]
    if facts.download_modules:
        parts.append("downloads third-party content to local disk")
    if facts.slow_modules:
        parts.append("slow (hours on a large target)")
    if facts.api_keys == "required":
        parts.append("needs API keys")
    return f"{', '.join(parts)}; {len(facts.modules)} BBOT modules."


def tool_description(entry):
    """A tool's description: the short tier, resident for the whole session."""
    # `when_to_use` is the one section that belongs in this tier: it is what
    # connects something an agent just discovered to the tool that acts on it, and
    # a tool nobody thinks to reach for is not chosen at all. The rest stays in the
    # long tier, where it is read once a tool has already been picked.
    trigger = " ".join(entry.capability.when_to_use.split())
    text = (
        f"{entry.capability.summary}\n\n"
        + (f"{trigger}\n\n" if trigger else "")
        + f"{behavior_line(entry.facts)}\n\n"
        + f"Call describe_tool('{entry.name}') for what it will miss, when not to use it, "
        f"and how to read its output."
    )
    return truncate(text, MAX_DESCRIPTION_CHARS, "shorten the preset's description: line")


def tool_details(entry):
    """Everything known about one capability: the long tier, fetched on demand."""
    cap = entry.capability
    facts = entry.facts

    out = [f"# `{cap.name}`\n\n{cap.summary}\n\n{behavior_line(facts)}\n"]
    out.append(_prose_section("When to use", cap.when_to_use))
    out.append(_prose_section("When not to use", cap.when_not_to_use))
    out.append(_prose_section("How it works", cap.how_it_works))
    out.append(_prose_section("How to call it", cap.how_to_call))
    out.append(_prose_section("Interpreting results", cap.interpreting_results))
    out.append(_prose_section("Caveats", cap.caveats))

    out.append("\n## What it produces\n\n")
    out.append(f"**Event types:** {', '.join(facts.produces) or 'nothing'}\n")
    if facts.download_modules:
        out.append(f"\n**Writes to local disk:** {', '.join(facts.download_modules)}\n")
    if facts.slow_modules:
        out.append(f"\n**Slow modules:** {', '.join(facts.slow_modules)}\n")
    if facts.unsafe_modules:
        out.append(f"\n**Not flagged safe:** {', '.join(facts.unsafe_modules)}\n")
    out.append(f"\n> {INTERNAL_MODULE_NOTE}\n")

    if facts.api_key_options:
        out.append(
            f"\n**API keys ({facts.api_keys}).** These modules do nothing until their key is set. "
            "A missing key soft-fails the module; the scan continues.\n\n"
        )
        out.append("\n".join(f"- `{opt}`" for opt in facts.api_key_options))
        out.append("\n")

    out.append(f"\n**Modules ({len(facts.modules)}):** {', '.join(f'`{m}`' for m in facts.modules)}\n")
    for module, subs in facts.submodules.items():
        out.append(f"\n**`{module}` submodules ({len(subs)}):** {', '.join(subs)}\n")

    out.append("\n## The preset this runs\n\n```yaml\n")
    out.append(yaml.safe_dump(cap.preset.to_preset_dict(), sort_keys=False, default_flow_style=False).strip())
    out.append("\n```\n")

    if cap.examples:
        out.append("\n## Examples\n\n")
        for example in cap.examples:
            out.append(f"- {example.description}\n  `{cap.name}(targets={example.targets})`\n")

    return truncate("".join(out), MAX_DETAILS_CHARS, "the module list and examples were cut")


def capabilities_table(entries):
    """One row per capability, for the generated docs page."""
    rows = [[e.name, e.facts.interaction, e.facts.noise, len(e.facts.modules), e.capability.summary] for e in entries]
    return _markdown_table(rows, ["Tool", "Interaction", "Noise", "Modules", "What it does"])
