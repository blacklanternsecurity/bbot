"""
Loads the capability preset files.

Each file in `capabilities/` is a real BBOT preset -- runnable with `bbot -p` --
carrying one extra `meta:` block that the scanner ignores. The filename is the
MCP tool name, `description:` is the short line an agent always sees, and `meta:`
holds the long prose it reads once it has decided to use the tool.

Files are loaded with `yaml.safe_load` + `Preset.from_dict`, never with
`Preset.from_yaml_file()`. That classmethod inserts the file's parent directory
at the front of the global preset search path and caches the result in a shared
mutable dict, which would let these shadow bundled presets for the rest of the
process, and would put them in `bbot -lp` where they don't belong.
"""

import logging
from functools import cached_property
from pathlib import Path

import yaml

from bbot.mcp.derive import derive
from bbot.mcp.models import Capability

log = logging.getLogger("bbot.mcp.registry")

CAPABILITY_DIR = Path(__file__).parent / "capabilities"


class CapabilityEntry:
    """A loaded capability plus its derived facts. Facts are derived on first
    access, because the first derivation pays ~0.25s to build BBOT's composite
    config schema and that shouldn't land in module import or test collection."""

    def __init__(self, capability, path):
        self.capability = capability
        self.path = path

    @property
    def name(self):
        return self.capability.name

    @cached_property
    def facts(self):
        facts = derive(self.capability.preset.to_preset_dict(), name=self.name)
        # A pseudotool that promises an event type its modules never emit would
        # return an empty result set that reads exactly like a clean target.
        impossible = sorted(set(self.capability.yields) - set(facts.produces))
        if impossible:
            raise ValueError(
                f'"{self.name}" declares yields: {", ".join(impossible)}, but its preset\'s modules '
                f"never produce {'that' if len(impossible) == 1 else 'those'}. "
                f"It can produce: {', '.join(facts.produces)}"
            )
        # BBOT withholds some event types from output by default. The modules
        # that make them still run and still feed everything downstream, they are
        # simply never handed to an output module -- and the scan's event stream
        # is one. A tool yielding an omitted type returns nothing at all, which
        # reads exactly like a clean target.
        from bbot.mcp.run import default_omitted_types

        preset_config = self.capability.preset.config or {}
        omitted = set(default_omitted_types()) - set(preset_config.get("omit_event_types") or [])
        silenced = sorted(set(self.capability.yields) & omitted)
        if silenced:
            raise ValueError(
                f'"{self.name}" yields {", ".join(silenced)}, which BBOT omits from output by default, '
                f"so the scan would return nothing. Set `config.omit_event_types` in the preset to a list "
                f"that leaves {'it' if len(silenced) == 1 else 'them'} out."
            )
        return facts


class Registry:
    def __init__(self, capability_dir=CAPABILITY_DIR):
        self.capability_dir = Path(capability_dir)
        self.entries = {}
        self._load()

    def _load(self):
        for path in sorted(self.capability_dir.rglob("*.yml")):
            with open(path) as f:
                raw = yaml.safe_load(f) or {}
            capability = Capability.from_preset_file(raw, name=path.stem)
            if capability.name in self.entries:
                raise ValueError(
                    f'duplicate tool name "{capability.name}" at {path} '
                    f"(already defined at {self.entries[capability.name].path})"
                )
            self.entries[capability.name] = CapabilityEntry(capability, path)

    def warm(self):
        """Derive every capability's facts up front. Called at server startup so
        the first agent request doesn't pay for the whole registry."""
        for entry in self.entries.values():
            _ = entry.facts

    def __len__(self):
        return len(self.entries)

    def __iter__(self):
        return iter(self.entries.values())

    def __contains__(self, name):
        return name in self.entries

    def get(self, name):
        """Look up a capability, raising with a suggestion if the name is wrong."""
        try:
            return self.entries[name]
        except KeyError:
            from bbot.core.helpers.misc import get_closest_match

            raise KeyError(get_closest_match(name, list(self.entries), msg="tool"))

    def sorted(self):
        return sorted(self, key=lambda e: e.name)


_REGISTRY = None


def get_registry():
    """The process-wide registry, loaded on first use."""
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = Registry()
    return _REGISTRY
