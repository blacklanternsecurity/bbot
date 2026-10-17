"""
Prints a draft pseudotool file: a BBOT preset with a `meta:` block attached.

Writes nothing. Paste the output into
`bbot/mcp/capabilities/<verb>_<noun>.yml`, replace the prose, and delete the
comment block at the top.

Everything the preset actually does is derived and shown as comments, so the
prose can be written against what the configuration really is rather than what
it was assumed to be. Those comments are the only place those facts appear: they
are recomputed on every load and must never be copied into the file.

    python -m bbot.mcp.scaffold find_subdomains_fast \\
        --include subdomain-enum --exclude-module dnsbrute --exclude-module dnsbrute_mutations

    python -m bbot.mcp.scaffold find_subdomains_deep \\
        --include subdomain-enum -c modules.dnsbrute.recursive_mutations=true
"""

import argparse
import re
import sys
import textwrap

import yaml

from bbot.mcp.derive import derive
from bbot.mcp.events import RENDERERS

# What `yields:` is set to in a draft. Deliberately not a real event type: it
# passes the model's shape check and then fails the derived-produces check with
# an error naming every type this preset can actually emit.
YIELDS_PLACEHOLDER = "TODO_CHOOSE_FROM_THE_LIST_ABOVE"

TEMPLATE = """\
description: TODO one line saying what this finds. It is the tool description, so keep it short.

{preset}

meta:
  yields:
    # The event types this tool's results are made of. Only these come back, so
    # pick what an agent actually wants from it, not everything BBOT emits on
    # the way there.
{yields_options}
    - {yields_placeholder}

  # REQUIRED. The one section that can talk an agent out of a tool it has
  # already chosen, which is why the long form is worth gating on.
  when_not_to_use: |
    TODO When is this the wrong choice, and what should be used instead? Cover
    rules of engagement, cost, and anything it will miss.

  # Everything below is OPTIONAL. Delete what this tool does not need rather
  # than filling in the form.

  how_to_call: |
    TODO How to actually drive this: scope semantics, which knobs matter, and
    what surprises people. Say what `strict_scope=True` changes here, and what
    belongs in `blacklist`. Only mention knobs the tool really accepts.

  when_to_use: |
    TODO Usually redundant with `description` above -- write this only if there
    is a situation the one-liner cannot convey.

  how_it_works: |
    TODO The mechanism, briefly. `describe_tool` already prints the derived
    module list, so write this only if the mechanism is surprising.

  interpreting_results: |
    TODO What the output means and what it does not prove. Returned alongside
    the results themselves, so write it for someone looking at them.

  caveats: |
    TODO Prerequisites, blind spots, and the ways this quietly under-delivers.

  examples:
    - description: TODO what this run accomplishes.
      targets: [evilcorp.com]
"""


def _comment_block(facts):
    dedicated = [t for t in facts.produces if t in RENDERERS]
    generic = [t for t in facts.produces if t not in RENDERERS]
    lines = [
        "# " + "-" * 74,
        "# Derived from the preset below. Do NOT copy these into the file -- they are",
        "# recomputed on every load. Shown here only so the prose can be accurate.",
        "#",
        f"#   interaction : {facts.interaction}",
        f"#   noise       : {facts.noise}",
        f"#   api keys    : {facts.api_keys}",
        f"#   modules ({len(facts.modules):>3}): {', '.join(facts.modules) or 'none'}",
        f"#   produces    : {', '.join(facts.produces) or 'nothing'}",
    ]
    if dedicated:
        lines.append(f"#   renders well: {', '.join(dedicated)}")
    if generic:
        lines.append(f"#   generic     : {', '.join(generic)}")
    if facts.slow_modules:
        lines.append(f"#   slow        : {', '.join(facts.slow_modules)}")
    if facts.unsafe_modules:
        lines.append(f"#   not safe    : {', '.join(facts.unsafe_modules)}")
    if facts.api_key_options:
        lines.append(f"#   key options : {', '.join(facts.api_key_options)}")
    lines.append("# " + "-" * 74)
    return "\n".join(
        "\n".join(textwrap.wrap(line, width=110, subsequent_indent="#                 ")) for line in lines
    )


def _yields_options(facts):
    """The produced types, as commented candidates. Types with a dedicated
    renderer come first, since those are the ones that return something an agent
    can read rather than a generic dump."""
    ordered = [t for t in facts.produces if t in RENDERERS] + [t for t in facts.produces if t not in RENDERERS]
    return "\n".join(f"    # - {t}{'' if t in RENDERERS else '   (generic rendering)'}" for t in ordered)


def build_preset(args):
    preset = {}
    for key, value in (
        ("include", args.include),
        ("modules", args.module),
        ("output_modules", args.output_module),
        ("exclude_modules", args.exclude_module),
        ("flags", args.flag),
        ("require_flags", args.require_flag),
        ("exclude_flags", args.exclude_flag),
    ):
        if value:
            preset[key] = value
    if args.config:
        from bbot.core.modules import MODULE_LOADER
        from bbot.scanner.preset.args import parse_dotted_cli

        preset["config"] = parse_dotted_cli(args.config, index=MODULE_LOADER.config_type_index)
    return preset


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m bbot.mcp.scaffold",
        description="Print a draft BBOT pseudotool: a preset plus its meta block. Writes nothing.",
    )
    parser.add_argument("name", help="tool name, lowercase verb_noun (e.g. find_subdomains_fast)")
    parser.add_argument("--include", action="append", default=[], metavar="PRESET", help="bundled preset to include")
    parser.add_argument("--module", action="append", default=[], metavar="MODULE")
    parser.add_argument("--output-module", action="append", default=[], metavar="MODULE")
    parser.add_argument("--exclude-module", action="append", default=[], metavar="MODULE")
    parser.add_argument("--flag", action="append", default=[], metavar="FLAG")
    parser.add_argument("--require-flag", action="append", default=[], metavar="FLAG")
    parser.add_argument("--exclude-flag", action="append", default=[], metavar="FLAG")
    parser.add_argument(
        "-c", "--config", action="append", default=[], metavar="KEY=VALUE", help="dotted config option, repeatable"
    )
    args = parser.parse_args(argv)

    # the filename becomes the MCP tool name, so reject a bad one here rather
    # than letting the file fail to load later
    if not re.fullmatch(r"[a-z][a-z0-9]*(_[a-z0-9]+)+", args.name):
        parser.error(f'"{args.name}" is not a valid tool name -- use lowercase verb_noun, e.g. find_subdomains_fast')

    preset = build_preset(args)
    if not preset:
        parser.error("give the tool something to do: --include, --module, or --flag")

    try:
        facts = derive(preset, name=args.name)
    except Exception as e:
        print(f"That preset does not build: {e}", file=sys.stderr)
        return 1
    if not facts.modules:
        print("That preset enables no scan modules, so the tool would find nothing.", file=sys.stderr)
        return 1

    print(_comment_block(facts))
    print(f"#\n# Save as: bbot/mcp/capabilities/{args.name}.yml\n")
    print(
        TEMPLATE.format(
            preset=yaml.safe_dump(preset, sort_keys=False, default_flow_style=False).strip(),
            yields_options=_yields_options(facts),
            yields_placeholder=YIELDS_PLACEHOLDER,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
