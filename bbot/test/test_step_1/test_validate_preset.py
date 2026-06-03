from ..bbot_fixtures import *  # noqa: F401

from bbot.scanner import validate_preset


def test_validate_preset_valid():
    errs = validate_preset({"modules": ["sslcert"], "config": {"scope": {"strict": True}}})
    assert errs == []


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


def test_from_yaml_string_raises_on_typos():
    """YAML strings carrying typos should also be rejected up front."""
    from bbot.errors import ValidationError as BBOTValidationError
    from bbot.scanner.preset import Preset

    import pytest

    with pytest.raises(BBOTValidationError) as excinfo:
        Preset.from_yaml_string("config:\n  scope:\n    strct: true\n")
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
