import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from bbot.core.config.models import PresetSchema

# Interaction levels, derived (never hand-written).
INTERACTIONS = ("none", "passive", "mixed", "active")

# Noise levels, derived (never hand-written).
NOISE_LEVELS = ("silent", "normal", "loud", "invasive")

# API-key tiers, derived (never hand-written).
API_KEY_TIERS = ("none", "optional", "required", "n/a")

# Prose that was scaffolded and never filled in. Rejected at load time rather
# than in a test, so a half-written tool can't reach an agent.
PLACEHOLDER_RE = re.compile(r"\b(TODO|TBD|FIXME|XXX)\b", re.I)

SUMMARY_MAX_LEN = 160

# Preset keys a tool may not set. Targets belong to the caller; the rest have no
# CLI-flag equivalent, which would make the emitted command lossy.
FORBIDDEN_PRESET_KEYS = (
    "target",
    "targets",
    "seeds",
    "blacklist",
    "conditions",
    "scan_name",
    "output_dir",
    "module_dirs",
    "verbose",
    "debug",
    "silent",
)


class CapabilityPresetSchema(PresetSchema):
    """
    The `preset:` block of a capability. A normal BBOT preset body, narrowed:
    no targets, and nothing that can't be round-tripped to a `bbot` command line.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    @model_validator(mode="after")
    def _reject_forbidden_keys(self):
        set_keys = [k for k in FORBIDDEN_PRESET_KEYS if getattr(self, k, None)]
        if set_keys:
            raise ValueError(
                f"a capability preset may not set: {', '.join(set_keys)} "
                f"(targets come from the caller; the rest have no CLI equivalent)"
            )
        return self

    def to_preset_dict(self):
        """The preset body as a plain dict, suitable for `Preset.from_dict()`."""
        return self.model_dump(exclude_none=True, by_alias=False)


class CapabilityExample(BaseModel):
    """A worked example. Structured rather than prose so the tests can run it."""

    model_config = ConfigDict(extra="forbid")

    description: str
    targets: list[str]


class CapabilityMeta(BaseModel):
    """The `meta:` block of a capability preset: everything an agent needs that
    the scanner has no use for."""

    model_config = ConfigDict(extra="forbid")

    # The only required prose in the long form. `description` already says what
    # a tool finds; this is the one section that can talk an agent out of a tool
    # it has already chosen, which is the whole reason the long form is gated.
    when_not_to_use: str

    # Everything below is optional. Write the ones that earn their place for a
    # given tool rather than filling in a form.
    when_to_use: str = ""

    # The event types this pseudotool's results are made of. A subdomain tool
    # yields DNS_NAME and nothing else; returning everything BBOT happened to
    # emit along the way would bury that. Each type is rendered by its own
    # renderer in `bbot.mcp.events`. Checked against what the preset actually
    # produces, so a tool cannot promise something it will never emit.
    yields: list[str] = Field(min_length=1)

    # What kind of target this tool is for. A subdomain tool takes domains; a
    # fuzzer takes URLs. Pointing either at the other's input wastes a scan, so
    # it is spelled out in the `targets` parameter rather than left to be
    # inferred from the tool's name.
    accepts: list[str] = Field(default_factory=lambda: ["DNS_NAME", "IP_ADDRESS", "IP_RANGE", "URL"])

    # How to actually drive this tool: the scope semantics that bite, which
    # knobs matter and when to reach for them. This is the part an agent needs
    # between deciding to use a tool and calling it.
    how_to_call: str = ""

    # `interpreting_results` and `caveats` are returned with the scan's results
    # rather than in the tool description: they are useless when choosing a tool
    # and valuable when reading its output, and keeping them out of the
    # description costs nothing in permanent context.
    how_it_works: str = ""
    interpreting_results: str = ""
    caveats: str = ""

    examples: list[CapabilityExample] = Field(default_factory=list)

    @field_validator("yields", "accepts")
    @classmethod
    def _valid_event_types(cls, v):
        for event_type in v:
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", event_type):
                raise ValueError(f'"{event_type}" is not a BBOT event type (they are SHOUTY_SNAKE_CASE)')
        return v

    @field_validator("when_not_to_use")
    @classmethod
    def _required_prose(cls, v, info):
        if not v or not v.strip():
            raise ValueError(f'"{info.field_name}" is required and must be non-empty')
        if PLACEHOLDER_RE.search(v):
            raise ValueError(f'"{info.field_name}" still contains a scaffold placeholder')
        return v.strip()

    @field_validator("when_to_use", "how_it_works", "how_to_call", "interpreting_results", "caveats")
    @classmethod
    def _optional_prose(cls, v, info):
        v = (v or "").strip()
        if v and PLACEHOLDER_RE.search(v):
            raise ValueError(f'"{info.field_name}" still contains a scaffold placeholder')
        return v


class Capability(BaseModel):
    """
    One BBOT preset, presented to an agent as a single tool.

    BBOT is one program that behaves like many, because a scan is just a module
    set fed into a recursive engine. A capability names one useful module set and
    wraps it in the prose an agent needs to choose it.

    The file on disk IS a BBOT preset -- runnable with `bbot -p` -- carrying one
    extra `meta:` block that the scanner ignores. `description` doubles as the
    tool summary, and the filename is the tool name. Everything describing
    behavior is derived from the preset, so it cannot drift.
    """

    model_config = ConfigDict(extra="forbid")

    # the MCP tool name the agent sees, taken from the filename, so it has to
    # read like one: verb_noun, optionally qualified (find_subdomains_deep).
    name: str
    summary: str
    meta: CapabilityMeta
    preset: CapabilityPresetSchema

    @classmethod
    def from_preset_file(cls, preset_dict, name):
        """Split a capability preset file into its agent metadata and its
        scanner body. `meta` is dropped from the body: the scanner ignores it,
        and keeping it out means what we bake is exactly what BBOT would run."""
        preset_dict = dict(preset_dict)
        meta = preset_dict.pop("meta", None)
        if meta is None:
            raise ValueError(f'capability "{name}" has no `meta:` block, so it cannot be presented as a tool')
        summary = preset_dict.get("description") or ""
        return cls(name=name, summary=summary, meta=meta, preset=preset_dict)

    # convenience so callers don't reach through `.meta` for the common fields
    @property
    def when_to_use(self):
        return self.meta.when_to_use

    @property
    def when_not_to_use(self):
        return self.meta.when_not_to_use

    @property
    def how_it_works(self):
        return self.meta.how_it_works

    @property
    def how_to_call(self):
        return self.meta.how_to_call

    @property
    def interpreting_results(self):
        return self.meta.interpreting_results

    @property
    def caveats(self):
        return self.meta.caveats

    @property
    def examples(self):
        return self.meta.examples

    @property
    def yields(self):
        return self.meta.yields

    @property
    def accepts(self):
        return self.meta.accepts

    @field_validator("name")
    @classmethod
    def _valid_tool_name(cls, v):
        if not re.fullmatch(r"[a-z][a-z0-9]*(_[a-z0-9]+)*", v):
            raise ValueError(
                f'invalid tool name "{v}" -- must be lowercase, words separated by underscores '
                f'(e.g. "find_subdomains" or "lightfuzz")'
            )
        return v

    @field_validator("summary")
    @classmethod
    def _summary_is_one_line(cls, v):
        """The preset's own `description` doubles as the tool summary, so it has
        to work as the opening line of a tool description."""
        if not v or not v.strip():
            raise ValueError("a capability preset needs a `description:` -- it becomes the tool summary")
        if PLACEHOLDER_RE.search(v):
            raise ValueError("`description:` still contains a scaffold placeholder")
        if "\n" in v.strip():
            raise ValueError("`description:` must be a single line -- it opens the tool description")
        if len(v) > SUMMARY_MAX_LEN:
            raise ValueError(f"`description:` is {len(v)} chars, max is {SUMMARY_MAX_LEN}")
        return v.strip()


class DerivedFacts(BaseModel):
    """
    Everything computed from a capability's preset. Never hand-written.
    """

    model_config = ConfigDict(extra="forbid")

    modules: list[str]
    output_modules: list[str]

    consumes: list[str]
    produces: list[str]
    # Event types this capability produces that it doesn't also consume. The
    # useful signal for what a scan will actually surface.
    produces_net: list[str]
    # True if any module watches "*". Never expanded, or every capability
    # containing such a module would claim to consume every event type.
    consumes_any: bool

    api_keys: str
    api_key_options: list[str]

    # Event types this scan will withhold from output, after the preset's own
    # config is applied. BBOT ships a default list and a preset replaces it
    # wholesale, so this is read off the baked config rather than reasoned about.
    omitted_types: list[str]

    interaction: str
    noise: str
    # Modules that write third-party content to local disk. A cost no other
    # part of this layer expresses: every other tool only makes requests.
    download_modules: list[str]
    slow_modules: list[str]
    unsafe_modules: list[str]
