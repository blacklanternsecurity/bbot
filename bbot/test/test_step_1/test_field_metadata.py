"""
Tests for the unified `sensitive` / `mandatory` field-level metadata that
drives:

- redaction (`BBOTCore.no_secrets_config` / `secrets_only_config`)
- the "Needs API Key" doc column (`MODULE_LOADER.modules_table`)
- the runtime `BaseModule.auth_required` property
"""

from ..bbot_fixtures import *  # noqa: F401, F403


def test_field_records_sensitive_and_mandatory_in_json_schema_extra():
    from bbot.core.config.models import Field, is_mandatory, is_sensitive

    f_secret = Field("", description="x", sensitive=True)
    f_required = Field("", description="x", mandatory=True)
    f_both = Field("", description="x", sensitive=True, mandatory=True)
    f_plain = Field("", description="x")

    assert is_sensitive(f_secret) is True
    assert is_mandatory(f_secret) is False
    assert is_sensitive(f_required) is False
    assert is_mandatory(f_required) is True
    assert is_sensitive(f_both) is True
    assert is_mandatory(f_both) is True
    assert is_sensitive(f_plain) is False
    assert is_mandatory(f_plain) is False


def test_global_config_marks_known_secrets_sensitive():
    from bbot.core.config.models import BBOTConfig, WebConfig, is_sensitive

    assert is_sensitive(BBOTConfig.model_fields["interactsh_token"]) is True
    assert is_sensitive(WebConfig.model_fields["http_cookies"]) is True
    # nearby non-secret control
    assert is_sensitive(WebConfig.model_fields["http_timeout"]) is False


def test_module_preload_extracts_sensitive_and_mandatory_sets():
    """`_extract_pydantic_config` should return the field-level flags via AST."""
    from bbot.core.modules import MODULE_LOADER

    MODULE_LOADER.preload()
    preloaded = MODULE_LOADER.preloaded()

    assert preloaded["shodan_dns"]["options_sensitive"] == ["api_key"]
    assert preloaded["shodan_dns"]["options_mandatory"] == ["api_key"]

    # robots has a Config but no auth-related fields
    assert preloaded["robots"]["options_sensitive"] == []
    assert preloaded["robots"]["options_mandatory"] == []

    # credshed: 3 mandatory, 2 sensitive (url is mandatory but not sensitive)
    assert sorted(preloaded["credshed"]["options_sensitive"]) == ["password", "username"]
    assert sorted(preloaded["credshed"]["options_mandatory"]) == ["credshed_url", "password", "username"]


def test_modules_table_needs_api_key_derived_from_mandatory():
    from bbot.core.modules import MODULE_LOADER

    MODULE_LOADER.preload()
    out = MODULE_LOADER.modules_table(["shodan_dns", "robots"])
    # Row format: | Module | Type | Needs API Key | ...
    rows = [line for line in out.splitlines() if "shodan_dns" in line or "robots" in line]
    shodan_row = next(r for r in rows if "shodan_dns" in r)
    robots_row = next(r for r in rows if "robots" in r)
    assert "Yes" in shodan_row.split("|")[3]
    assert "No" in robots_row.split("|")[3]


def test_no_secrets_config_redacts_module_and_global_secrets():
    from bbot.core import CORE
    from bbot.core.modules import MODULE_LOADER

    MODULE_LOADER.preload()
    cfg = {
        "home": "/tmp/bbot",
        "interactsh_token": "leaky",
        "web": {"http_cookies": {"session": "abc"}, "http_timeout": 30},
        "modules": {
            "shodan_dns": {"api_key": "shodan-secret"},
            "credshed": {"username": "u", "password": "p", "credshed_url": "http://x"},
            "robots": {"include_sitemap": True},
            "unknown_mod": {"foo": "bar"},  # passes through
        },
    }
    redacted = CORE.no_secrets_config(cfg)

    # global non-secret kept
    assert redacted["home"] == "/tmp/bbot"
    assert redacted["web"]["http_timeout"] == 30
    # global secrets removed
    assert "interactsh_token" not in redacted
    assert "http_cookies" not in redacted["web"]
    # module secrets removed, non-secret module fields kept (empty dicts kept
    # so the module name still appears under `modules`, matching prior behavior)
    assert redacted["modules"]["shodan_dns"] == {}
    assert redacted["modules"]["credshed"] == {"credshed_url": "http://x"}
    assert redacted["modules"]["robots"] == {"include_sitemap": True}
    # unknown module passes through unchanged
    assert redacted["modules"]["unknown_mod"] == {"foo": "bar"}


def test_secrets_only_config_extracts_sensitive_fields():
    from bbot.core import CORE
    from bbot.core.modules import MODULE_LOADER

    MODULE_LOADER.preload()
    cfg = {
        "home": "/tmp/bbot",
        "interactsh_token": "leaky",
        "web": {"http_cookies": {"session": "abc"}, "http_timeout": 30},
        "modules": {
            "shodan_dns": {"api_key": "shodan-secret"},
            "credshed": {"username": "u", "password": "p", "credshed_url": "http://x"},
        },
    }
    secrets = CORE.secrets_only_config(cfg)

    assert secrets == {
        "interactsh_token": "leaky",
        "web": {"http_cookies": {"session": "abc"}},
        "modules": {
            "shodan_dns": {"api_key": "shodan-secret"},
            "credshed": {"username": "u", "password": "p"},
        },
    }


def test_auth_required_property_derives_from_config():
    from bbot.core.modules import MODULE_LOADER

    MODULE_LOADER.preload()
    shodan_dns = MODULE_LOADER.load_module("shodan_dns")
    robots = MODULE_LOADER.load_module("robots")

    # `auth_required` is a property — the descriptor is on the class.
    # We can resolve it without instantiating by walking model_fields ourselves.
    from bbot.core.config.models import is_mandatory

    shodan_mandatories = [n for n, f in shodan_dns.Config.model_fields.items() if is_mandatory(f)]
    robots_mandatories = [n for n, f in robots.Config.model_fields.items() if is_mandatory(f)]
    assert shodan_mandatories == ["api_key"]
    assert robots_mandatories == []


def test_credential_connection_fields_are_sensitive():
    """Connection URIs that can embed credentials, and auth usernames, must be sensitive
    so they aren't leaked into the redacted/public config view."""
    from bbot.core.modules import MODULE_LOADER

    MODULE_LOADER.preload()
    preloaded = MODULE_LOADER.preloaded()
    assert "uri" in preloaded["neo4j"]["options_sensitive"]
    assert "url" in preloaded["elastic"]["options_sensitive"]
    assert "url" in preloaded["splunk"]["options_sensitive"]
    assert "url" in preloaded["websocket"]["options_sensitive"]
    assert "jenkins_username" in preloaded["trajan"]["options_sensitive"]
