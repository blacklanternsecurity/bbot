from pathlib import Path

import pytest
import yaml

from ..bbot_fixtures import *  # noqa F401

import bbot
from bbot.core.modules import MODULE_LOADER
from bbot.mcp import events as event_render
from bbot.mcp.cli import flatten_config, preset_to_cli, preset_to_yaml, render_config_value
from bbot.mcp.compose import ComposeError, prepare, validate_targets
from bbot.mcp.derive import derive
from bbot.mcp.models import PLACEHOLDER_RE, SUMMARY_MAX_LEN, Capability
from bbot.mcp.registry import CAPABILITY_DIR, Registry, get_registry

REQUIRED_PROSE = ("when_not_to_use",)

MINIMAL = {
    "description": "A one-line summary.",
    "modules": ["portscan"],
    "meta": {"yields": ["OPEN_TCP_PORT"], "when_not_to_use": "Don't."},
}


@pytest.fixture(scope="module")
def registry():
    reg = get_registry()
    reg.warm()
    return reg


def test_capability_files_load():
    """Every shipped pseudotool parses. The model rejects empty and placeholder
    prose, so loading cleanly is itself the prose check."""
    files = sorted(CAPABILITY_DIR.rglob("*.yml"))
    assert files, f"no pseudotool files found under {CAPABILITY_DIR}"
    assert len(Registry()) == len(files), "a pseudotool file failed to register"


def test_capability_files_are_real_bbot_presets():
    """The file on disk has to be runnable with `bbot -p`, not just readable by
    this server. That is the whole reason `meta:` is a legal preset key."""
    from bbot.scanner.preset import validate_preset

    for path in sorted(CAPABILITY_DIR.rglob("*.yml")):
        raw = yaml.safe_load(path.read_text())
        errors = validate_preset(raw)
        assert not errors, f"{path.name} is not a valid BBOT preset: {'; '.join(str(e) for e in errors)}"


def test_tool_names_match_their_filenames(registry):
    """The filename is the MCP tool name, so it has to be usable as one."""
    import re

    for entry in registry:
        assert entry.name == entry.path.stem, f"{entry.path} does not match its tool name"
        assert re.fullmatch(r"[a-z][a-z0-9]*(_[a-z0-9]+)*", entry.name), entry.name


def test_invalid_tool_names_rejected():
    """A single word is fine (`lightfuzz`); anything a Python identifier would
    reject is not, since the name becomes the MCP tool name."""
    for bad in ("FindSubdomains", "find-subdomains", "9find_x", "find__x", "find_", "_find", "find x"):
        with pytest.raises(ValueError):
            Capability.from_preset_file(MINIMAL, name=bad)


def test_capability_prose_required(registry):
    for entry in registry:
        cap = entry.capability
        for field in REQUIRED_PROSE:
            value = getattr(cap, field)
            assert value and value.strip(), f'"{cap.name}" at {entry.path} is missing "{field}".'
            assert not PLACEHOLDER_RE.search(value), f'"{cap.name}" has a scaffold placeholder in "{field}".'
        assert len(cap.summary) <= SUMMARY_MAX_LEN
        assert "\n" not in cap.summary


def test_prose_rejects_placeholders_and_blanks():
    """The model, not just a test, refuses unfinished prose."""
    Capability.from_preset_file(MINIMAL, name="find_things")
    for field in REQUIRED_PROSE:
        for bad in ("TODO: write this", "   "):
            broken = {**MINIMAL, "meta": {**MINIMAL["meta"], field: bad}}
            with pytest.raises(ValueError):
                Capability.from_preset_file(broken, name="find_things")
    # description doubles as the tool summary, so it is required too
    with pytest.raises(ValueError):
        Capability.from_preset_file({**MINIMAL, "description": ""}, name="find_things")
    with pytest.raises(ValueError):
        Capability.from_preset_file({**MINIMAL, "description": "x" * (SUMMARY_MAX_LEN + 1)}, name="find_things")


def test_only_when_not_to_use_is_required():
    """A minimal pseudotool is a short line, what it yields, and when not to
    reach for it. Everything else in the long form is opt-in."""
    cap = Capability.from_preset_file(MINIMAL, name="find_things")
    assert cap.when_not_to_use
    for optional in ("when_to_use", "how_it_works", "how_to_call", "interpreting_results", "caveats"):
        assert getattr(cap, optional) == ""
    assert cap.examples == []


def test_a_file_without_meta_is_not_a_pseudotool():
    with pytest.raises(ValueError, match="meta"):
        Capability.from_preset_file({"description": "x", "modules": ["portscan"]}, name="find_things")


def test_preset_body_rejects_targets_and_conditions():
    """A pseudotool may not carry targets or anything with no CLI equivalent."""
    for bad in ({"targets": ["evilcorp.com"]}, {"conditions": ["{{ warn('x') }}"]}, {"output_dir": "/tmp/x"}):
        with pytest.raises(ValueError):
            Capability.from_preset_file({**MINIMAL, **bad}, name="find_things")


def test_capability_presets_bake(registry):
    for entry in registry:
        assert entry.facts.modules, f'"{entry.name}" enables no scan modules.'
        assert entry.facts.interaction in ("passive", "active", "mixed")
        assert entry.facts.api_keys in ("none", "optional", "required")


def test_yields_are_actually_produced(registry):
    """A pseudotool promising an event type its modules never emit would return
    an empty result set that reads exactly like a clean target."""
    for entry in registry:
        assert entry.capability.yields
        assert set(entry.capability.yields) <= set(entry.facts.produces), entry.name


def test_yields_are_checked_against_the_preset(tmp_path):
    (tmp_path / "find_nothing.yml").write_text(
        yaml.safe_dump({**MINIMAL, "meta": {**MINIMAL["meta"], "yields": ["EMAIL_ADDRESS"]}})
    )
    registry = Registry(capability_dir=tmp_path)
    with pytest.raises(ValueError, match="never produce"):
        registry.warm()


def test_yields_must_not_be_omitted_by_bbot(tmp_path):
    """BBOT withholds some event types from output. A tool yielding one returns
    nothing at all, which reads exactly like a clean target.

    The check reads the *baked* config, because `omit_event_types` in a preset
    replaces BBOT's default list rather than adding to it."""
    silenced = {**MINIMAL, "config": {"omit_event_types": ["OPEN_TCP_PORT"]}}
    (tmp_path / "find_silence.yml").write_text(yaml.safe_dump(silenced))
    with pytest.raises(ValueError, match="omits from output"):
        Registry(capability_dir=tmp_path).warm()


def test_un_omitting_a_type_satisfies_the_check(tmp_path):
    """A tool may return an omitted type by replacing the list without it."""
    allowed = {**MINIMAL, "config": {"omit_event_types": ["RAW_TEXT"]}}
    (tmp_path / "find_ports.yml").write_text(yaml.safe_dump(allowed))
    registry = Registry(capability_dir=tmp_path)
    registry.warm()
    facts = registry.get("find_ports").facts
    assert "OPEN_TCP_PORT" not in facts.omitted_types
    assert facts.omitted_types == ["RAW_TEXT"], "the preset's list replaces the default wholesale"


def test_shipped_tools_return_what_they_promise(registry):
    """Every yielded type must survive the scan's own output filter."""
    for entry in registry:
        overlap = set(entry.capability.yields) & set(entry.facts.omitted_types)
        assert not overlap, f'"{entry.name}" yields {sorted(overlap)} but its scan withholds them'


def test_accepts_describes_the_targets_parameter(registry):
    """A subdomain tool takes domains and a fuzzer takes URLs; pointing either at
    the other's input wastes a whole scan."""
    from bbot.mcp.format import targets_description

    for entry in registry:
        assert entry.capability.accepts
        description = targets_description(entry)
        assert description[0].isupper()
        if entry.capability.accepts == ["DNS_NAME"]:
            assert "Domains and hostnames to scan" in description
            assert "URL" not in description


def test_every_yielded_type_renders(registry):
    """Each event type a pseudotool yields needs a puller that makes sense of it."""
    for entry in registry:
        for event_type in entry.capability.yields:
            sample = [{"type": event_type, "data": "example.com", "host": "example.com", "module": "m", "tags": []}]
            rendered = event_render.render(sample)
            assert event_type in rendered
            assert rendered[event_type].strip(), f"{event_type} rendered empty"


def test_a_tool_names_the_modules_its_prose_promises(registry):
    """A pseudotool that advertises a capability should enable the module for it
    rather than inheriting it from a bundled preset that may change."""
    promises = {"lightfuzz": ["nowafpls"], "lightfuzz_deep": ["nowafpls"]}
    for name, required in promises.items():
        if name not in registry:
            continue
        declared = set(registry.get(name).capability.preset.modules or [])
        for module in required:
            assert module in declared, f'"{name}" relies on inheriting `{module}`; name it in `modules:`'
            assert module in registry.get(name).facts.modules


def test_fuzzers_try_waf_bypasses_rather_than_skipping(registry):
    """`avoid_wafs` is a three-way setting, not a bool. `try_bypasses` probes each
    WAF-protected host with nowafpls padding and fuzzes it only if that gets
    through, which is what the prose promises. `always` would silently skip those
    hosts and `never` would fuzz blindly into a WAF."""
    from bbot.mcp.derive import bake_preset_dict

    for name in ("lightfuzz", "lightfuzz_deep"):
        if name not in registry:
            continue
        entry = registry.get(name)
        _, baked = bake_preset_dict(entry.capability.preset.to_preset_dict(), name=name)
        assert baked.config["modules"]["lightfuzz"]["avoid_wafs"] == "try_bypasses"
        # a finding that only landed because of padding has to say so
        assert "used-nowafpls" in entry.capability.interpreting_results


def test_bypass_provenance_is_surfaced():
    """A finding reached only by padding past a WAF will not reproduce without
    the same padding, so the tag has to survive into the rendered result."""
    rendered = event_render.render(
        [
            {
                "type": "FINDING",
                "data": {"severity": "HIGH", "description": "SQLi", "url": "https://x/p"},
                "host": "x",
                "module": "lightfuzz",
                "tags": ["used-nowafpls", "in-scope"],
            }
        ]
    )["FINDING"]
    assert "used-nowafpls" in rendered
    assert "in-scope" not in rendered, "only provenance tags are worth the space"


def test_derivation_invariants():
    """The interaction and noise rules assume these hold across BBOT's modules.

    Restricted to shipped modules: other test files register deliberately
    malformed fixture modules on the global loader."""
    shipped = Path(bbot.__file__).parent / "modules"
    for name, module in MODULE_LOADER.preloaded().items():
        if module.get("type") != "scan" or not Path(module["path"]).is_relative_to(shipped):
            continue
        flags = set(module.get("flags", []))
        assert len({"active", "passive"} & flags) == 1, (
            f'Scan module "{name}" must carry exactly one of active/passive; has {sorted(flags)}.'
        )
        assert {"safe", "loud", "invasive"} & flags, f'Scan module "{name}" carries no safety flag.'
        for option in module.get("options_mandatory", []):
            assert option in module["config"], f'"{name}" marks unknown option "{option}" mandatory.'


def test_derivation_is_pure(registry):
    """Deriving twice must agree. `Preset.bake()` shallow-copies its source, so a
    derivation that reused a Preset object would return stale results here."""
    for entry in registry:
        preset_dict = entry.capability.preset.to_preset_dict()
        assert derive(preset_dict, name=entry.name) == derive(preset_dict, name=entry.name)
        assert derive(preset_dict, name=entry.name) == entry.facts


def test_bundled_includes_are_not_shadowed(tmp_path):
    """A pseudotool's `include:` must resolve to the preset BBOT ships.

    `PresetPath.find()` matches on filename across every directory on the global
    search path, so an unrelated YAML can otherwise take priority."""
    from bbot.scanner.preset.path import PRESET_PATH

    from bbot.mcp.derive import resolve_bundled_includes

    decoy = tmp_path / "subdomain-enum.yml"
    decoy.write_text("modules:\n  - portscan\n")
    original = list(PRESET_PATH.paths)
    try:
        PRESET_PATH.add_path(tmp_path)
        resolved = resolve_bundled_includes({"include": ["subdomain-enum"]})["include"]
        assert resolved[0].endswith("bbot/presets/subdomain-enum.yml")
        assert str(decoy) != resolved[0]
    finally:
        PRESET_PATH.paths = original


def test_examples_run(registry):
    for entry in registry:
        for example in entry.capability.examples:
            targets, blacklist, _ = prepare(entry, example.targets)
            assert targets == example.targets
            assert preset_to_cli(entry.capability.preset.to_preset_dict(), targets, blacklist).startswith("bbot -t ")


def test_targets_are_not_read_as_files(registry, tmp_path):
    """`Preset.from_dict` reads any target that resolves to a file and splits it
    into targets. Model-supplied targets must never reach that path."""
    canary = "canary.internal.evilcorp.com"
    target_file = tmp_path / "targets.txt"
    target_file.write_text(f"{canary}\n")
    entry = next(iter(registry))
    for bad in (str(target_file), "README.md", "/etc/hostname"):
        with pytest.raises(ComposeError) as excinfo:
            prepare(entry, [bad])
        assert canary not in str(excinfo.value)


def test_targets_reject_garbage():
    """Hostile strings must produce a ComposeError, never an uncaught exception:
    the filesystem lookup that guards against file-path targets raises on some
    of them by itself."""
    for bad in ("not a valid target!!", "**", "[", "\x00null", "a" * 5000, "", "   ", "$(whoami)", "."):
        with pytest.raises(ComposeError):
            validate_targets([bad])
    with pytest.raises(ComposeError):
        validate_targets([])
    with pytest.raises(ComposeError):
        validate_targets(["evilcorp.com"], blacklist=["\x00null"])


def test_targets_accept_real_ones():
    for target in ("evilcorp.com", "1.2.3.0/24", "https://evilcorp.com/a", "bob@evilcorp.com"):
        assert validate_targets([target])[0] == [target]


def test_cli_roundtrip(registry):
    """The emitted `-c` options must parse back into the preset's config."""
    from bbot.scanner.preset.args import parse_dotted_cli

    for entry in registry:
        config = entry.capability.preset.to_preset_dict().get("config") or {}
        if not config:
            continue
        entries = [f"{path}={render_config_value(value)}" for path, value in flatten_config(config)]
        assert parse_dotted_cli(entries, index=MODULE_LOADER.config_type_index) == config, entry.name


def test_no_secrets_in_output(registry):
    """Emitted commands must never carry the operator's configured API keys.
    `Preset.to_dict()` would, because a Preset copies the global CORE whose
    custom_config is bbot.yml deep-merged with secrets.yml."""
    from bbot.core import CORE

    canary = "CANARY_SECRET_VALUE"
    original = CORE.custom_config
    try:
        CORE.merge_custom({"modules": {"shodan_dns": {"api_key": canary}}})
        for entry in registry:
            preset_dict = entry.capability.preset.to_preset_dict()
            blob = preset_to_cli(preset_dict, ["evilcorp.com"], []) + preset_to_yaml(preset_dict, ["evilcorp.com"])
            assert canary not in blob
            assert "shodan_dns" not in blob
    finally:
        CORE.custom_config = original


def test_registry_rejects_duplicate_name(tmp_path):
    for sub in ("a", "b"):
        (tmp_path / sub).mkdir()
        (tmp_path / sub / "find_things.yml").write_text(yaml.safe_dump(MINIMAL))
    with pytest.raises(ValueError, match="duplicate tool name"):
        Registry(capability_dir=tmp_path)


def test_registry_get_suggests_on_typo(registry):
    with pytest.raises(KeyError, match="find_subdomains_fast"):
        registry.get("find_subdomains_fas")


def test_dependency_check_covers_every_tool_and_installs_nothing(registry):
    """The server must never install anything by itself: an image that already
    has the binaries (bbot-docker-full) should see no action at all."""
    from bbot.mcp import deps

    required = deps.required_modules(registry)
    assert required
    # the union of every tool's modules, not all of BBOT's
    for entry in registry:
        assert set(entry.facts.modules) <= set(required)
    assert len(required) < len(MODULE_LOADER.preloaded())

    installable, privileged = deps.report(registry)
    # the two are kept apart because only one of them is an install problem:
    # reporting a root-at-runtime module as needing an install makes --check-deps
    # demand a fix that --install-deps then reports as already done
    assert not (set(installable) & set(privileged))
    for group in (installable, privileged):
        assert set(group) <= set(required)
        for reasons in group.values():
            assert reasons and all(isinstance(r, str) and r for r in reasons)


def test_dependency_check_finds_binaries_in_bbots_own_tools_dir(registry, monkeypatch, tmp_path):
    """BBOT downloads binaries into its tools directory rather than onto PATH,
    so a check that only consults PATH reports false positives for masscan,
    massdns, trufflehog and the rest."""
    from bbot.mcp import deps

    monkeypatch.setattr(deps, "_tools_dir", lambda: tmp_path)
    monkeypatch.setattr(deps.shutil, "which", lambda _: None)
    without_tools, _ = deps.report(registry)
    assert without_tools, "with nothing on PATH and an empty tools dir, something must be missing"

    for name in set(without_tools):
        (tmp_path / name).touch()
        module = MODULE_LOADER.preloaded().get(name) or {}
        for binary in deps._binaries(module):
            (tmp_path / binary).touch()
    still_missing, _ = deps.report(registry)
    # only pip-based gaps can survive, since those do not live in the tools dir
    for name, reasons in still_missing.items():
        assert all("pip package" in r or "needs root" in r for r in reasons), (name, reasons)


def test_only_runtime_escalation_counts_as_a_privilege_problem(registry):
    """The preloaded `sudo` flag means installing needs root, which is a different
    question from a module that escalates while scanning. Warning on the flag
    alone flags dnsbrute, jadx and git_clone, which run fine once installed."""
    from bbot.core.modules import MODULE_LOADER
    from bbot.mcp import deps

    preloaded = MODULE_LOADER.preloaded()
    flagged = {m for m in deps.required_modules(registry) if preloaded[m].get("sudo")}
    escalating = {m for m in flagged if deps._escalates_at_runtime(preloaded[m]["path"])}
    assert escalating < flagged, "the flag is broader than actual runtime escalation"
    assert "portscan" in escalating, "portscan calls ensure_root() from setup()"
    for name in ("dnsbrute", "dnscommonsrv"):
        if name in flagged:
            assert name not in escalating, f"{name} only needs root to install"


def test_module_config_can_come_from_the_environment():
    """A containerised server has no writable secrets.yml, and the MCP client
    that invokes `docker run` can only pass an env block. BBOT has no env-var
    config mechanism of its own, so this bridges the two."""
    from bbot.mcp import deps

    config = deps.config_from_env(
        {
            "BBOT_MODULES_SHODAN_DNS_API_KEY": "abc",
            "BBOT_MODULES_GITHUB_ORG_API_KEY": "def",
            "PATH": "/usr/bin",
            "BBOT_MODULES_SHODAN_DNS_API_KEY_EMPTY": "",
        }
    )
    # module names contain underscores, so this must resolve against the real
    # module list rather than by splitting on "_"
    assert config == {"modules": {"shodan_dns": {"api_key": "abc"}, "github_org": {"api_key": "def"}}}
    assert deps.config_from_env({"BBOT_MODULES_NOT_A_MODULE_API_KEY": "x"}) == {}
    assert deps.config_from_env({}) == {}


def test_api_key_status_never_exposes_values(registry, monkeypatch):
    """Presence only. Key values must not reach anything an agent can read."""
    from bbot.core import CORE
    from bbot.mcp import deps

    canary = "CANARY_KEY_VALUE"
    original = CORE.custom_config
    try:
        CORE.merge_custom({"modules": {"shodan_dns": {"api_key": canary}}})
        configured, missing = deps.api_key_status(registry)
        blob = repr(configured) + repr(missing)
        assert canary not in blob
        if "shodan_dns" in configured:
            assert configured["shodan_dns"] == ["modules.shodan_dns.api_key"]
    finally:
        CORE.custom_config = original


def test_event_renderers():
    """Each type gets a shape that suits it, rather than one generic dump."""
    rendered = event_render.render(
        [
            {"type": "DNS_NAME", "data": "a.evilcorp.com", "host": "a.evilcorp.com", "module": "crt", "tags": []},
            {"type": "DNS_NAME", "data": "a.evilcorp.com", "host": "a.evilcorp.com", "module": "otx", "tags": []},
            {"type": "DNS_NAME", "data": "b.evilcorp.com", "host": "b.evilcorp.com", "module": "crt", "tags": []},
            {
                "type": "FINDING",
                "data": {"description": "exposed .git", "url": "https://evilcorp.com/.git/", "severity": "HIGH"},
                "host": "evilcorp.com",
                "module": "git",
                "tags": [],
                "why": "found by excavate",
            },
            {
                "type": "STORAGE_BUCKET",
                "data": {"name": "evilcorp-backups", "url": "https://s3/evilcorp-backups"},
                "host": "s3",
                "module": "bucket_amazon",
                "tags": ["open-bucket"],
            },
            {"type": "MOBILE_APP", "data": "com.evilcorp.app", "host": None, "module": "apk", "tags": []},
        ]
    )
    # bare list, deduplicated
    assert rendered["DNS_NAME"] == "a.evilcorp.com\nb.evilcorp.com"
    # severity and the discovery sentence both survive
    assert "[HIGH]" in rendered["FINDING"] and "exposed .git" in rendered["FINDING"]
    assert "found by excavate" in rendered["FINDING"]
    # existing and readable are different answers
    assert "[OPEN]" in rendered["STORAGE_BUCKET"]
    # an unknown type still renders rather than vanishing
    assert "com.evilcorp.app" in rendered["MOBILE_APP"]


def test_event_renderer_paginates():
    events = [{"type": "DNS_NAME", "data": f"h{i}.evilcorp.com", "module": "m", "tags": []} for i in range(50)]
    rendered = event_render.render(events, limit=10)["DNS_NAME"]
    assert rendered.count("\n") == 10
    assert "and 40 more" in rendered
