"""
Derives an agent-facing description of what a BBOT configuration actually does,
by baking its preset and inspecting the resulting module set.

This module is the only place in `bbot.mcp` that calls `Preset.bake()`.

`bake()` shallow-copies its source (`preset.py`, `baked_preset = copy(self)`,
with no `__copy__` defined), so a baked preset shares its mutable sets with the
original and re-baking returns stale results. Everything here therefore builds a
throwaway `Preset` from a deep-copied dict, bakes it exactly once, and keeps only
plain data.
"""

from copy import deepcopy

from bbot.errors import ValidationError
from bbot.mcp.models import DerivedFacts

# Internal modules run for nearly every configuration, so folding their event
# types into a capability's would make every capability look identical.
# Reported once at the registry level instead.
INTERNAL_MODULE_NOTE = (
    "BBOT's internal modules (dnsresolve, excavate, speculate, cloudcheck, ...) run for "
    "every scan and additionally produce DNS_NAME, IP_ADDRESS, OPEN_TCP_PORT, URL_UNVERIFIED, "
    "FINDING and RAW_DNS_RECORD. They are excluded from per-capability event lists."
)


def resolve_bundled_includes(preset_dict):
    """
    Rewrite `include:` entries to absolute paths under BBOT's bundled preset
    directory.

    `PresetPath.find()` rglobs every directory anything has added to the global
    preset search path, and matches on filename alone. A stray YAML elsewhere on
    that path can therefore shadow a bundled preset: `include: [tech-detect]`
    resolving to a nuclei template named `tech-detect.yaml` is a real observed
    case. A capability's derived facts have to describe the preset BBOT ships, so
    resolve these here instead of letting the search path decide.

    Only the bake sees the absolute paths. The composed dict keeps the bare names,
    because those are what a user types after `-p`.
    """
    from bbot.scanner.preset.path import DEFAULT_PRESET_PATH

    includes = preset_dict.get("include")
    if not includes:
        return preset_dict

    resolved = []
    for include in includes:
        for extension in (".yml", ".yaml"):
            matches = sorted(DEFAULT_PRESET_PATH.rglob(f"**/{include}{extension}"))
            if matches:
                resolved.append(str(matches[0]))
                break
        else:
            from bbot.core.helpers.misc import get_closest_match

            available = sorted(p.stem for ext in ("yml", "yaml") for p in DEFAULT_PRESET_PATH.rglob(f"**/*.{ext}"))
            raise ValidationError(get_closest_match(include, available, msg="bundled preset"))
    return {**preset_dict, "include": resolved}


def bake_preset_dict(preset_dict, name="capability", bundled_includes=True):
    """
    Validate and bake a preset dict. Returns `(preset, baked)`.

    `preset` is the unbaked object, kept only because `_is_valid_module()` on it
    answers "why was this module dropped". Neither object may be baked again.

    `bundled_includes` pins `include:` entries to BBOT's shipped presets, which is
    right for capabilities. Pass False for a preset a user wrote, where an
    `include:` may legitimately name one of their own.
    """
    from bbot.scanner import Preset

    preset_dict = deepcopy(preset_dict)
    if bundled_includes:
        preset_dict = resolve_bundled_includes(preset_dict)
    preset = Preset.from_dict(preset_dict, name=name, _log=False)
    # bake() enforces this itself, but failing here gives a better error site
    preset.validate()
    return preset, preset.bake()


def derive(preset_dict, name="capability", bundled_includes=True):
    """Derive the facts an agent needs from a preset body."""
    preset, baked = bake_preset_dict(preset_dict, name=name, bundled_includes=bundled_includes)
    return facts_from_baked(preset, baked)


def facts_from_baked(preset, baked):
    """Build `DerivedFacts` from an already-baked preset."""
    preloaded = baked.module_loader.preloaded()
    scan_modules = sorted(baked.scan_modules)

    consumes = set()
    produces = set()
    for module in scan_modules:
        consumes.update(preloaded[module]["watched_events"])
        produces.update(preloaded[module]["produced_events"])
    consumes_any = "*" in consumes
    consumes.discard("*")
    produces.discard("*")

    module_flags = {m: set(preloaded[m].get("flags", [])) for m in scan_modules}
    api_keys, api_key_options = _derive_api_keys(preset, scan_modules, preloaded)

    return DerivedFacts(
        modules=scan_modules,
        output_modules=sorted(baked.output_modules),
        consumes=sorted(consumes),
        produces=sorted(produces),
        produces_net=sorted(produces - consumes),
        consumes_any=consumes_any,
        api_keys=api_keys,
        api_key_options=api_key_options,
        omitted_types=sorted(str(t) for t in (baked.config.get("omit_event_types") or [])),
        interaction=_derive_interaction(module_flags),
        noise=_derive_noise(module_flags),
        download_modules=sorted(m for m, f in module_flags.items() if "download" in f),
        slow_modules=sorted(m for m, f in module_flags.items() if "slow" in f),
        unsafe_modules=sorted(m for m, f in module_flags.items() if "safe" not in f),
    )


def _derive_api_keys(preset, scan_modules, preloaded):
    """
    Classify how much this configuration depends on API keys.

    The distinction that matters is explicitly-named modules vs. flag-swept ones.
    A preset with `flags: [subdomain-enum]` pulls in dozens of key-gated modules
    but works fine with none of them set, because a module missing its key
    soft-fails and the scan continues. A capability that names `shodan_dns`
    outright is genuinely dead without one.
    """
    needs_key = {m: preloaded[m]["options_mandatory"] for m in scan_modules if preloaded[m].get("options_mandatory")}

    if not scan_modules:
        tier = "n/a"
    elif not needs_key:
        tier = "none"
    elif len(needs_key) == len(scan_modules):
        tier = "required"
    else:
        explicit = set(preset.explicit_scan_modules) & set(scan_modules)
        tier = "required" if explicit and explicit <= set(needs_key) else "optional"

    options = sorted(f"modules.{module}.{opt}" for module, opts in needs_key.items() for opt in opts)
    return tier, options


def _derive_interaction(module_flags):
    """Whether this configuration touches the target. Every scan module carries
    exactly one of `active`/`passive` (asserted in the tests)."""
    if not module_flags:
        return "none"
    has_active = any("active" in f for f in module_flags.values())
    has_passive = any("passive" in f for f in module_flags.values())
    if not has_active:
        return "passive"
    if not has_passive:
        return "active"
    return "mixed"


def _derive_noise(module_flags):
    """
    How much of this the target will notice.

    Passive wins outright: a module can be flagged both `passive` and `loud`
    (`ipneighbor`, for one), meaning it queries third parties heavily but never
    contacts the target. From the target's side that is still silence.

    Deliberately not a numeric score. `safe` is set on the large majority of scan
    modules and carries almost no signal, so the useful output is the explicit
    `unsafe_modules` / `slow_modules` lists alongside this label.
    """
    if _derive_interaction(module_flags) == "passive":
        return "silent"
    if any("invasive" in f for f in module_flags.values()):
        return "invasive"
    if any("loud" in f for f in module_flags.values()):
        return "loud"
    return "normal"
