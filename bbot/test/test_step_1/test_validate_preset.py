from ..bbot_fixtures import *  # noqa: F401

from bbot.scanner import validate_preset


def test_validate_preset_valid():
    errs = validate_preset({"modules": ["sslcert"], "config": {"scope": {"strict": True}}})
    assert errs == []


def test_module_version_config_validation():
    """Module `version` options accept version-like strings only."""
    assert validate_preset({"modules": ["retirejs"], "config": {"modules": {"retirejs": {"version": "5.4.0"}}}}) == []
    errs = validate_preset({"modules": ["retirejs"], "config": {"modules": {"retirejs": {"version": "5.3.0 oops #"}}}})
    assert len(errs) >= 1
    assert any("version" in e.message for e in errs)


def test_home_config_validation():
    """`home` is interpolated into dependency commands, so it rejects shell metacharacters."""
    assert validate_preset({"config": {"home": "/tmp/mybbot"}}) == []
    errs = validate_preset({"config": {"home": "/tmp/x;id>/tmp/pwned;#"}})
    assert len(errs) >= 1
    assert any("home" in e.message or "shell metacharacters" in e.message for e in errs)


def test_validate_preset_typo_top_level():
    errs = validate_preset({"modlues": ["nuclei"]})
    assert len(errs) == 1
    assert errs[0].where == "preset"
    assert "modlues" in errs[0].message


def test_validate_preset_typo_in_config():
    errs = validate_preset({"config": {"scope": {"strct": True}}})
    assert len(errs) == 1
    assert errs[0].where == "config"
    assert "strct" in errs[0].message
    assert errs[0].path == "scope.strct"


def test_validate_preset_wrong_type():
    errs = validate_preset({"config": {"web": {"http_timeout": "not-a-number"}}})
    assert len(errs) == 1
    assert errs[0].where == "config"
    assert errs[0].path == "web.http_timeout"
    assert "integer" in errs[0].message


def test_validate_preset_unknown_module():
    errs = validate_preset({"modules": ["nucleii"]})
    # closest-match suggestion: "Could not find module 'nucleii'. Did you mean 'nuclei'?"
    assert any('"nucleii"' in str(e) and "nuclei" in str(e) for e in errs)


def test_validate_preset_unknown_module_option():
    """Typo in a known module's option key gets tagged `module:<name>`."""
    errs = validate_preset({"config": {"modules": {"nuclei": {"tgas": "apache"}}}})
    assert len(errs) == 1
    assert errs[0].where == "module:nuclei"
    assert errs[0].path == "tgas"
    assert "tgas" in errs[0].message


def test_validate_preset_wrong_type_on_module_option():
    """Known module option with wrong type (nuclei.ratelimit is int)."""
    errs = validate_preset({"config": {"modules": {"nuclei": {"ratelimit": "not-a-number"}}}})
    assert len(errs) == 1
    assert errs[0].where == "module:nuclei"
    assert errs[0].path == "ratelimit"
    assert "integer" in errs[0].message


def test_validate_preset_unknown_module_in_config():
    """Unknown module name nested under config.modules gets a clean error."""
    errs = validate_preset({"config": {"modules": {"nucleii": {"tgas": "x"}}}})
    # closest-match: "Could not find module 'nucleii'. Did you mean 'nuclei'?"
    assert any('"nucleii"' in str(e) and "nuclei" in str(e) for e in errs)


def test_validate_preset_multiple_errors():
    """A preset with several typos should produce errors for all of them, not just the first."""
    errs = validate_preset(
        {
            "modlues": ["x"],  # typo in top-level key
            "config": {
                "scope": {"strct": True},  # typo in config section
                "web": {"http_timeout": "bad"},  # wrong type
            },
        },
    )
    assert len(errs) >= 3
    messages = " ".join(str(e) for e in errs)
    assert "modlues" in messages
    assert "strct" in messages
    assert "http_timeout" in messages


def test_validate_preset_non_dict():
    errs = validate_preset(["not a dict"])
    assert len(errs) == 1
    assert "dict" in errs[0].message


def test_validate_preset_config_modules_as_list():
    """`config.modules` given as a list (wrong shape) used to crash with IndexError."""
    errs = validate_preset({"config": {"modules": ["nuclei"]}})
    assert len(errs) == 1
    assert errs[0].where == "config"
    assert errs[0].path == "modules"


def test_validate_preset_module_dirs_as_string():
    """`module_dirs` as a string used to iterate characters and raise PermissionError."""
    errs = validate_preset({"module_dirs": "/tmp/foo"})
    assert any(e.path == "module_dirs" and "list" in e.message for e in errs)


def test_validate_preset_modules_as_string_no_cascade():
    """`modules: "nuclei"` (string instead of list) should NOT produce per-character lookups."""
    errs = validate_preset({"modules": "nuclei"})
    # exactly one type error, no per-character bogus suggestions
    assert len(errs) == 1
    assert errs[0].path == "modules"
    assert "list" in errs[0].message


def test_validate_preset_non_string_module_entry_no_crash():
    """A non-string entry in modules/output_modules/exclude_modules (e.g. a dangling YAML
    list item -> None) must be reported as a type error, never raise TypeError."""
    # dangling YAML item -> None
    errs = validate_preset({"modules": ["nuclei", None]})
    assert len(errs) == 1
    assert errs[0].path == "modules.1"
    assert "string" in errs[0].message and "None" in errs[0].message

    # a typo alongside the bad entry: both surface, still no crash
    errs = validate_preset({"modules": ["nucleii", None]})
    assert len(errs) == 2
    assert any('Did you mean "nuclei"' in str(e) for e in errs)

    # int and unhashable (dict) entries must not crash the set membership / difflib calls
    errs = validate_preset({"output_modules": [123], "exclude_modules": [{"a": 1}]})
    assert len(errs) == 2
    assert all("string" in e.message for e in errs)


def test_validate_preset_top_level_typo_suggests_preset_field():
    """Typos at the preset root should suggest preset field names, not config paths."""
    cases = [
        ("modlues", "modules"),
        ("flgas", "flags"),
        ("targest", "target"),
        ("output_moduels", "output_modules"),
    ]
    for typo, expected in cases:
        errs = validate_preset({typo: ["x"]})
        assert any(f'"{typo}"' in str(e) and f'"{expected}"' in str(e) for e in errs), (
            f"expected suggestion {expected!r} for typo {typo!r}, got: {[str(e) for e in errs]}"
        )


def test_validate_preset_file_missing_returns_error():
    """A missing preset path should be reported as a single error, not raised."""
    from bbot.scanner import validate_preset_file

    errs = validate_preset_file("/tmp/does-not-exist-bbot-fuzz.yml")
    assert len(errs) == 1
    assert "not found" in errs[0].message.lower()


def test_from_dict_raises_on_typos():
    """from_dict() should reject typo'd preset dicts up front instead of letting
    them flow through to bake()."""
    from bbot.errors import ValidationError as BBOTValidationError
    from bbot.scanner.preset import Preset

    import pytest

    with pytest.raises(BBOTValidationError) as excinfo:
        Preset.from_dict({"modlues": ["nuclei"]})
    assert "modlues" in str(excinfo.value)


def test_from_yaml_string_raises_on_top_level_typo():
    """A top-level key typo in a YAML string is rejected up front by from_dict's gate."""
    from bbot.errors import ValidationError as BBOTValidationError
    from bbot.scanner.preset import Preset

    import pytest

    with pytest.raises(BBOTValidationError) as excinfo:
        Preset.from_yaml_string("flgas:\n  - subdomain-enum\n")
    assert "flgas" in str(excinfo.value)


def test_from_yaml_config_typo_deferred_to_validate():
    """A config-VALUE typo passes the top-level key gate; validate() catches it, not load."""
    from bbot.errors import ValidationError as BBOTValidationError
    from bbot.scanner.preset import Preset

    import pytest

    preset = Preset.from_yaml_string("config:\n  scope:\n    strct: true\n")
    assert preset._validated is False
    with pytest.raises(BBOTValidationError) as excinfo:
        preset.validate()
    assert "strct" in str(excinfo.value)


def test_validate_preset_interactsh_server_accepts_valid():
    """interactsh_server accepts FQDNs, IPv4, IPv6, None, and empty string."""
    for v in ["example.com", "sub.example.com", "192.168.1.1", "::1", "", None]:
        errs = validate_preset({"config": {"interactsh_server": v}})
        assert errs == [], f"expected {v!r} to validate, got: {[str(e) for e in errs]}"


def test_validate_preset_interactsh_server_rejects_invalid():
    """A single-label hostname (a value without any dots, e.g. a typo'd
    domain where the user forgot the TLD) or a value with whitespace must
    be rejected at preset-load time, before any module tries to register
    with the interactsh server."""
    for v in ["badhost", "localhost", "with spaces.com"]:
        errs = validate_preset({"config": {"interactsh_server": v}})
        assert len(errs) == 1, f"expected {v!r} to fail validation"
        assert errs[0].path == "interactsh_server"
        assert "FQDN or IP" in errs[0].message
        assert repr(v) in errs[0].message


def test_bundled_presets_validate_clean():
    """Every YAML preset shipped under bbot/presets/ must pass validation."""
    from pathlib import Path
    import bbot
    from bbot.scanner import validate_preset_file

    presets_dir = Path(bbot.__file__).parent / "presets"
    failures = {}
    for preset_path in sorted(presets_dir.rglob("*.yml")):
        errs = validate_preset_file(preset_path)
        if errs:
            failures[str(preset_path.relative_to(presets_dir))] = [str(e) for e in errs]
    assert not failures, "bundled presets failed validation:\n" + "\n".join(
        f"  {name}:\n    " + "\n    ".join(msgs) for name, msgs in failures.items()
    )


def test_defaults_yml_validates_against_schema():
    """BBOT's own defaults.yml must pass its own validator. Guards against the pydantic
    schema (core/config/models.py) silently drifting from defaults.yml -- if a key is
    added/renamed in defaults.yml, the schema must keep up or this fails."""
    import yaml
    from pathlib import Path
    import bbot

    defaults = yaml.safe_load((Path(bbot.__file__).parent / "defaults.yml").read_text())
    errs = validate_preset({"config": defaults})
    assert errs == [], "defaults.yml must validate clean:\n" + "\n".join(str(e) for e in errs)


def test_validate_preset_sql_retries_settable():
    """`retries` is read by the shared SQLTemplate.setup, so each concrete SQL output
    module must declare it in its Config (otherwise it's rejected as an unknown option)."""
    for module in ("postgres", "mysql", "sqlite"):
        errs = validate_preset({"config": {"modules": {module: {"retries": 5}}}})
        assert errs == [], f"{module}.retries should validate, got: {[str(e) for e in errs]}"


def test_validate_preset_wordlist_accepts_list():
    """*_wordlist fields document a list form (merge multiple wordlists); the validating
    path must accept a list, not only a string. Regression for a documented-feature break."""
    for module, field in [
        ("dnsbrute", "wordlist"),
        ("paramminer_headers", "wordlist"),
        ("webbrute", "wordlist"),
        ("legba", "ssh_wordlist"),
    ]:
        errs = validate_preset({"config": {"modules": {module: {field: ["/tmp/a.txt", "/tmp/b.txt"]}}}})
        assert errs == [], f"{module}.{field} list form should validate, got: {[str(e) for e in errs]}"


def test_validate_preset_nuclei_mode_lowercase_literal():
    """nuclei.mode is a lowercase Literal: lowercase values pass; anything else (incl.
    mixed case) is rejected with the allowed values listed."""
    assert validate_preset({"config": {"modules": {"nuclei": {"mode": "manual"}}}}) == []
    errs = validate_preset({"config": {"modules": {"nuclei": {"mode": "MANUAL"}}}})
    assert len(errs) == 1
    assert errs[0].where == "module:nuclei" and errs[0].path == "mode"
    assert "Expected one of" in errs[0].message and "'manual'" in errs[0].message


def test_validate_preset_bad_module_dir_returns_errors(tmp_path):
    """A custom module_dir containing an unloadable module (here a legacy options dict,
    which preload rejects via sys.exit) must surface as an error, not kill the caller."""
    from bbot.core.modules import ModuleLoader

    mod_dir = tmp_path / "badmods"
    mod_dir.mkdir()
    (mod_dir / "legacymod.py").write_text(
        "from bbot.modules.base import BaseModule\n"
        "class legacymod(BaseModule):\n"
        '    watched_events = ["DNS_NAME"]\n'
        '    produced_events = ["DNS_NAME"]\n'
        '    flags = ["passive", "safe"]\n'
        '    meta = {"description": "x", "created_date": "2025-01-01", "author": "@x"}\n'
        '    options = {"foo": "bar"}\n'
        '    options_desc = {"foo": "a foo"}\n'
    )
    # isolated loader so the bad dir doesn't pollute the global one
    errs = validate_preset(
        {"module_dirs": [str(mod_dir)], "modules": ["legacymod"]},
        module_loader=ModuleLoader(),
    )
    assert any(e.path == "module_dirs" for e in errs), [str(e) for e in errs]


def test_build_validation_schema_tolerates_unexecable_config():
    """A custom module whose `class Config` references a module-level name (valid at real
    import, but unresolvable in the isolated exec namespace) must not break schema building.
    The module falls back to accepting any config rather than being rejected."""
    from bbot.core.modules import _build_validation_schema

    preloaded = {
        "synthmod": {
            "config_source": (
                "class Config(BaseModuleConfig):\n    threads: int = Field(MY_UNDEFINED_CONSTANT, description='x')\n"
            ),
        },
    }
    schema = _build_validation_schema(preloaded)  # must not raise
    # the module is usable and accepts arbitrary config (lenient fallback)
    assert schema.model_validate({"config": {"modules": {"synthmod": {"threads": 5, "anything": "x"}}}})


def test_validate_preset_baddns_subclass_severity_is_validated():
    """baddns_direct/baddns_zone validate min_severity/min_confidence against the shared
    severity/confidence Literal (case-insensitive), not accept arbitrary strings."""
    assert validate_preset({"config": {"modules": {"baddns_direct": {"min_severity": "low"}}}}) == []
    errs = validate_preset({"config": {"modules": {"baddns_zone": {"min_severity": "BOGUS"}}}})
    assert len(errs) == 1 and errs[0].path == "min_severity"
    assert "Expected one of" in errs[0].message


def test_validate_preset_deprecated_options_still_validate():
    """Deprecated options are ignored, but presets that still set them must keep validating."""
    for module in ("shodan_idb", "discord", "slack", "teams"):
        assert validate_preset({"config": {"modules": {module: {"retries": 3}}}}) == []


def test_deprecated_options_have_no_defaults():
    from bbot.core.modules import MODULE_LOADER

    for module in ("shodan_idb", "discord", "slack", "teams"):
        assert "retries" not in MODULE_LOADER.preloaded()[module]["config"]


def test_find_deprecated_config():
    from bbot.core.modules import MODULE_LOADER
    from bbot.core.config.models import find_deprecated_config

    config = {
        "web": {"http_retries": 1},
        "modules": {"slack": {"retries": 5, "webhook_url": "https://example.com"}, "shodan_idb": {"retries": 2}},
    }
    assert find_deprecated_config(config, MODULE_LOADER.config_schema) == {
        "modules.slack.retries": "",
        "modules.shodan_idb.retries": "",
    }
    assert find_deprecated_config({"modules": {"slack": {"webhook_url": "x"}}}, MODULE_LOADER.config_schema) == {}
    # a deprecation can say what to use instead
    assert find_deprecated_config({"module_dirs": ["/tmp/x"]}, MODULE_LOADER.config_schema) == {
        "module_dirs": "Set module_dirs at the top level of a preset and load it with -p."
    }


async def test_deprecated_option_warns_at_scan_start(caplog):
    from bbot.scanner import Scanner

    scan = Scanner(config={"modules": {"shodan_idb": {"retries": 3}}})
    await scan._prep()
    assert 'Config option "modules.shodan_idb.retries" is deprecated and will be ignored' in caplog.text


async def test_config_module_dirs_is_a_noop(tmp_path, caplog):
    from bbot.scanner import Scanner

    mod_dir = tmp_path / "mods"
    mod_dir.mkdir()
    (mod_dir / "noopmod.py").write_text(
        "from bbot.modules.base import BaseModule\n"
        "class noopmod(BaseModule):\n"
        '    watched_events = ["DNS_NAME"]\n'
        '    produced_events = ["DNS_NAME"]\n'
        '    flags = ["passive", "safe", "subdomain-enum"]\n'
        '    meta = {"description": "x", "created_date": "2025-01-01", "author": "@x"}\n'
    )
    scan = Scanner(config={"module_dirs": [str(mod_dir)]}, flags=["subdomain-enum"])
    await scan._prep()
    assert (
        'Config option "module_dirs" is deprecated and will be ignored. '
        "Set module_dirs at the top level of a preset and load it with -p." in caplog.text
    )
    assert mod_dir.resolve() not in scan.preset.module_loader.module_dirs
    assert "noopmod" not in scan.modules


def test_validate_preset_lightfuzz_avoid_wafs_accepts_bool():
    """lightfuzz.avoid_wafs is a tri-state that also accepts the boolean form, so configs
    written against the older bool option still load. Unknown values are still rejected."""
    for value in (True, False, "ALWAYS", " never "):
        assert validate_preset({"config": {"modules": {"lightfuzz": {"avoid_wafs": value}}}}) == []
    errs = validate_preset({"config": {"modules": {"lightfuzz": {"avoid_wafs": "bogus"}}}})
    assert len(errs) == 1 and errs[0].path == "avoid_wafs"
    assert "Expected one of" in errs[0].message


async def test_lightfuzz_avoid_wafs_bool_coerced_at_runtime():
    """Schema validation doesn't rewrite the runtime config, so lightfuzz must apply the same
    coercion when it reads the option. True means 'always' (skip), False means 'never' (fuzz raw)."""
    from bbot.scanner import Scanner

    for value, expected in ((True, "always"), (False, "never"), ("ALWAYS", "always"), (" never ", "never")):
        scan = Scanner(
            "http://127.0.0.1", presets=["lightfuzz"], config={"modules": {"lightfuzz": {"avoid_wafs": value}}}
        )
        await scan._prep()
        assert scan.modules["lightfuzz"].avoid_wafs == expected, (
            f"avoid_wafs={value!r} became {scan.modules['lightfuzz'].avoid_wafs!r}, expected {expected!r}"
        )


def test_validate_preset_untrusted_module_dir_runs_no_code(tmp_path):
    """A module dir refused by the loader's trust prompt is never read, so its Config class never executes."""
    from bbot.core.modules import ModuleLoader

    mod_dir = tmp_path / "mods"
    mod_dir.mkdir()
    canary = tmp_path / "canary"
    (mod_dir / "canarymod.py").write_text(
        "from bbot.modules.base import BaseModule\n"
        "from bbot.core.config.models import BaseModuleConfig, Field\n"
        "class canarymod(BaseModule):\n"
        '    watched_events = ["DNS_NAME"]\n'
        '    produced_events = ["DNS_NAME"]\n'
        '    flags = ["passive", "safe"]\n'
        '    meta = {"description": "x", "created_date": "2025-01-01", "author": "@x"}\n'
        "    class Config(BaseModuleConfig):\n"
        f"        _canary = __import__('pathlib').Path({str(canary)!r}).write_text('ran')\n"
        '        foo: str = Field("", description="foo")\n'
    )
    preset = {"module_dirs": [str(mod_dir)], "modules": ["canarymod"]}

    asked = []
    loader = ModuleLoader()
    loader.confirm_module_dir = lambda module_dir, module_names, notes: (
        asked.append((module_dir, module_names)) or False
    )
    errs = validate_preset(preset, module_loader=loader)
    assert asked == [(mod_dir.resolve(), ["canarymod"])]
    assert any(e.path == "module_dirs" and "not trusted" in e.message for e in errs), [str(e) for e in errs]
    assert "canarymod" not in loader.preloaded()
    assert not canary.exists()

    # trusting the folder loads it, and validating then executes its Config class
    loader.confirm_module_dir = lambda module_dir, module_names, notes: True
    assert validate_preset(preset, module_loader=loader) == []
    assert canary.read_text() == "ran"


def test_validate_preset_config_module_dirs_is_ignored(tmp_path):
    """`module_dirs` only works as a top-level preset key. As a config option it's deprecated: accepted, but nothing is loaded."""
    from bbot.core.modules import ModuleLoader

    loader = ModuleLoader()
    assert validate_preset({"config": {"module_dirs": [str(tmp_path)]}}, module_loader=loader) == []
    assert tmp_path.resolve() not in loader.module_dirs


def test_validate_preset_misplaced_preset_key():
    """A top-level preset key nested under `config:` points the user back to the top level."""
    errs = validate_preset({"config": {"include": ["subdomain-enum"]}})
    assert len(errs) == 1, [str(e) for e in errs]
    assert '"include" is a top-level preset option' in errs[0].message
