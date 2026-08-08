import re

import pytest

from ..bbot_fixtures import *  # noqa F401

pytest.importorskip("mcp", reason="the mcp extra is not installed")

from bbot.mcp import format as fmt  # noqa E402
from bbot.mcp.registry import get_registry  # noqa E402
from bbot.mcp.server import INSTRUCTIONS, create_server  # noqa E402

# The tools that are not generated from a preset file.
FIXED_TOOLS = {"list_tools", "describe_tool", "scan_status", "scan_results", "scan_stop"}

# Imperatives that current models over-trigger on. Tool descriptions should say
# when to call something, not shout about it.
PRESSURE_WORDS = ("CRITICAL", "MUST ", "ALWAYS ", "NEVER ", "IMPORTANT:")


@pytest.fixture(scope="module")
def registry():
    reg = get_registry()
    reg.warm()
    return reg


@pytest.fixture(scope="module")
def server():
    return create_server()


async def call(_server, _tool, **kwargs):
    """Invoke a tool and return its text. The parameters are underscore-prefixed
    so they can't collide with a tool's own argument names."""
    result = await _server.call_tool(_tool, kwargs)
    content = result[0] if isinstance(result, tuple) else result
    return "".join(block.text for block in content)


async def test_every_pseudotool_becomes_a_tool(server, registry):
    """One tool per preset file, plus the fixed set."""
    names = {t.name for t in await server.list_tools()}
    assert names == FIXED_TOOLS | {e.name for e in registry}
    assert "scan" not in names, "there is no generic scanner; each preset is its own tool"


async def test_list_tools_returns_the_whole_menu(server, registry):
    """The catalog is reachable in one call, and it is the complete set."""
    listing = await call(server, "list_tools")
    for entry in registry:
        assert entry.name in listing
        assert entry.capability.summary in listing
        assert entry.facts.interaction in listing
    # summaries only -- the long prose stays behind describe_tool
    for entry in registry:
        assert entry.capability.when_not_to_use not in listing


async def test_tool_descriptions(server):
    for tool in await server.list_tools():
        assert len(tool.description) >= 150, f'"{tool.name}" description is too thin to guide a caller'
        assert len(tool.description) <= fmt.MAX_DESCRIPTION_CHARS
        for word in PRESSURE_WORDS:
            assert word not in tool.description, f'"{tool.name}" uses pressure language: {word}'
        for param, schema in tool.inputSchema.get("properties", {}).items():
            assert schema.get("description"), f'"{tool.name}" parameter "{param}" has no description'


async def test_pseudotool_signature_stays_small(server, registry):
    """Every parameter is re-declared on every generated tool, so the signature
    is what decides whether this scales."""
    for tool in [t for t in await server.list_tools() if t.name in registry]:
        assert set(tool.inputSchema["properties"]) == {"targets", "blacklist", "strict_scope"}
        assert tool.inputSchema["required"] == ["targets"]


async def test_short_description_carries_what_selection_needs(server, registry):
    """The short tier is resident all session; it has to say what the tool finds
    and what it does to the target, and nothing more."""
    tools = {t.name: t for t in await server.list_tools()}
    for entry in registry:
        description = tools[entry.name].description
        assert entry.capability.summary in description
        assert entry.facts.interaction in description
        assert entry.facts.noise in description
        assert "describe_tool" in description
        # the long prose belongs in describe_tool, not here
        for prose in (entry.capability.when_not_to_use, entry.capability.when_to_use):
            if prose.strip():
                assert prose not in description


async def test_only_far_reaching_tools_require_reading_the_details_first(registry):
    """A gate on every tool taxes first contact with a research step, and an agent
    that meets a refusal the first time it reaches for something learns not to
    reach. A gate on none loses the caveat for the tools whose blast radius is not
    in the request: what they touch is in the detail, and nothing can check it."""
    fresh = create_server()
    gated = sorted(e.name for e in registry if e.capability.force_require_tool)
    ungated = sorted(e.name for e in registry if not e.capability.force_require_tool)
    assert gated, "the far-reaching tools should still be gated"
    assert ungated, "gating everything is what this exists to avoid"

    # An ungated tool is not stopped. Checked with a target it will reject, so the
    # reply proves the gate was passed without a scan actually being launched.
    reply = await call(fresh, ungated[0], targets=["   "])
    assert "before running it" not in reply
    assert "Could not start this scan" in reply

    refusal = await call(fresh, gated[0], targets=["evilcorp.com"])
    assert "before running it" in refusal
    assert "scan_id" not in refusal

    details = await call(fresh, "describe_tool", name=gated[0])
    assert "## When not to use" in details
    assert "## How to call it" in details
    assert len(details) <= fmt.MAX_DETAILS_CHARS

    # reading one tool's details does not unlock another
    for other in gated[1:]:
        assert "before running it" in await call(fresh, other, targets=["evilcorp.com"])


async def test_a_wrong_call_is_refused_and_says_where_the_contract_is(registry):
    """Enforcement moves from before the call to the call itself, so the refusal
    has to carry what the pre-flight gate used to teach."""
    fresh = create_server()
    ungated = sorted(e.name for e in registry if not e.capability.force_require_tool)

    for garbage in ([], ["   "], ["/etc/passwd"], ["x" * 600]):
        reply = await call(fresh, ungated[0], targets=garbage)
        assert "Could not start this scan" in reply, garbage
        assert "describe_tool" in reply, garbage
        assert "scan_id" not in reply, garbage


async def test_details_only_name_knobs_that_exist(server, registry):
    """The long tier is where 'how do I actually call this' lives, and every
    knob it tells the agent to pass has to be a real parameter. Prose writes a
    tool argument as `name=value` and a BBOT config option as `name: value`,
    so only the former is a promise this checks.

    What each knob means is not prose's job -- the parameter descriptions carry
    that, on every generated tool, and are covered by the signature and
    description tests above."""
    tools = {t.name: t for t in await server.list_tools()}
    for entry in registry:
        details = await call(server, "describe_tool", name=entry.name)
        declared = set(tools[entry.name].inputSchema["properties"])
        named = set(re.findall(r"`([a-z_][a-z0-9_]*)\s*=", details))
        assert named <= declared, f"{entry.name} tells the agent to pass {sorted(named - declared)}"


async def test_describe_tool_unknown_name_suggests(server, registry):
    name = sorted(e.name for e in registry)[0]
    assert name in await call(server, "describe_tool", name=name[:-1])


async def test_unknown_scan_id_says_which_exist(server):
    for tool in ("scan_results", "scan_stop", "scan_status"):
        assert "unknown scan_id" in await call(server, tool, scan_id="nope")


async def test_bad_targets_are_refused(registry):
    fresh = create_server()
    name = sorted(e.name for e in registry)[0]
    await call(fresh, "describe_tool", name=name)
    for bad in ("README.md", "not a valid target!!"):
        result = await call(fresh, name, targets=[bad])
        assert "Could not start this scan" in result
        assert "scan_id" not in result


async def test_scan_results_advertises_what_it_withheld(server):
    """The agent should know the chain and the raw record exist without paying
    for them, so the tool says so and names the parameters."""
    tools = {t.name: t for t in await server.list_tools()}
    schema = tools["scan_results"].inputSchema["properties"]
    assert set(schema) == {"scan_id", "since", "limit", "detail", "full_records"}
    assert "discovery chain" in schema["detail"]["description"]
    assert "output.json" in schema["full_records"]["description"]
    # both descriptions have to say what they cost, or an agent cannot budget
    assert "Costs" in schema["detail"]["description"]
    assert "Large" in schema["full_records"]["description"]


async def test_instructions_stay_small():
    """The catalog is the tool list, so the instructions carry workflow only."""
    assert len(INSTRUCTIONS) <= 1500
    assert "describe_tool" in INSTRUCTIONS
