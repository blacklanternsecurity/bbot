from ..bbot_fixtures import *  # noqa: F401

from bbot.scanner import validate_preset


def test_validate_preset_valid():
    errs = validate_preset({"modules": ["sslcert"], "config": {"scope": {"strict": True}}})
    assert errs == []


def test_validate_preset_typo_top_level():
    errs = validate_preset({"modlues": ["nuclei"]}, validate_modules=False)
    assert len(errs) == 1
    assert errs[0].where == "preset"
    assert "modlues" in errs[0].message


def test_validate_preset_typo_in_config():
    errs = validate_preset({"config": {"scope": {"strct": True}}}, validate_modules=False)
    assert len(errs) == 1
    assert errs[0].where == "config"
    assert "strct" in errs[0].message
    assert errs[0].path == "scope.strct"


def test_validate_preset_wrong_type():
    errs = validate_preset({"config": {"web": {"http_timeout": "not-a-number"}}}, validate_modules=False)
    assert len(errs) == 1
    assert errs[0].where == "config"
    assert errs[0].path == "web.http_timeout"
    assert "integer" in errs[0].message


def test_validate_preset_unknown_module():
    errs = validate_preset({"modules": ["nucleii"]})
    assert any('Unknown module: "nucleii"' in str(e) for e in errs)


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
        validate_modules=False,
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
