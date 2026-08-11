import stat
import tempfile

from ..bbot_fixtures import *  # noqa F401

from bbot.scanner import Scanner, Preset
from bbot.test.worker import worker_dir


# FUTURE TODO:
# Consider testing possible edge cases:
#  make sure custom module load directory works with cli arg module/flag/config syntax validation
#   what if you specify -c modules.custommodule.option?
#    the validation needs to not happen until after your custom preset preset has been loaded
#   what if you specify flags in one preset, but another preset (loaded later) has more custom modules that match that flag?
#    how do we make sure those other modules get loaded too?
#   what if you specify a flag that's only on custom modules? Will it be rejected as invalid?


def test_preset_descriptions():
    # ensure very preset has a description
    preset = Preset()
    for loaded_preset, category, preset_path, original_filename in preset.all_presets.values():
        assert loaded_preset.description, (
            f'Preset "{loaded_preset.name}" at {original_filename} does not have a description.'
        )


def test_core():
    from bbot.core import CORE

    assert "testasdf" not in CORE.default_config
    assert "testasdf" not in CORE.custom_config
    assert "testasdf" not in CORE.config

    core_copy = CORE.copy()
    # custom_config is mutable per-instance; default/merged config should not leak back
    core_copy.custom_config["testasdf"] = "test"
    assert "testasdf" not in CORE.custom_config
    assert "testasdf" not in CORE.config
    assert "testasdf" in core_copy.custom_config
    # force a re-merge by reading .config
    assert "testasdf" in core_copy.config

    # test config merging
    config_to_merge = {"test123": {"test321": [3, 2, 1], "test456": [4, 5, 6]}}
    core_copy.merge_custom(config_to_merge)
    assert "test123" not in core_copy.default_config
    assert "test123" in core_copy.custom_config
    assert "test123" in core_copy.config
    assert "test321" in core_copy.custom_config["test123"]
    assert "test321" in core_copy.config["test123"]

    # test deletion
    del core_copy.custom_config["test123"]["test321"]
    # force re-merge
    core_copy._config = None
    assert "test123" in core_copy.custom_config
    assert "test123" in core_copy.config
    assert "test321" not in core_copy.custom_config["test123"]
    assert "test321" not in core_copy.config["test123"]
    assert "test456" in core_copy.custom_config["test123"]
    assert "test456" in core_copy.config["test123"]


async def test_preset_yaml(clean_default_config):
    import yaml

    preset1 = Preset(
        "evilcorp.ce",
        seeds=["evilcorp.com", "www.evilcorp.ce"],
        blacklist=["test.www.evilcorp.ce"],
        modules=["sslcert"],
        output_modules=["json"],
        exclude_modules=["ipneighbor"],
        flags=["subdomain-enum"],
        require_flags=["safe"],
        exclude_flags=["slow"],
        verbose=False,
        debug=False,
        silent=True,
        config={"keep_scans": 42},
    )
    preset1 = preset1.validate().bake()
    assert "evilcorp.com" in preset1.target.seeds
    assert "evilcorp.ce" not in preset1.target.seeds
    assert "asdf.www.evilcorp.ce" in preset1.target.seeds
    assert "evilcorp.ce" in preset1.target.target
    assert "asdf.evilcorp.ce" in preset1.target.target
    assert "test.www.evilcorp.ce" in preset1.blacklist
    assert "asdf.test.www.evilcorp.ce" in preset1.blacklist
    assert "sslcert" in preset1.scan_modules
    assert preset1.in_target("evilcorp.ce")
    assert preset1.in_target("www.evilcorp.ce")
    assert not preset1.in_target("evilcorp.com")
    assert preset1.blacklisted("test.www.evilcorp.ce")
    assert preset1.blacklisted("asdf.test.www.evilcorp.ce")
    assert not preset1.blacklisted("www.evilcorp.ce")

    # test yaml save/load
    yaml1 = preset1.to_yaml(sort_keys=True)
    preset2 = Preset.from_yaml_string(yaml1)
    yaml2 = preset2.to_yaml(sort_keys=True)
    assert yaml1 == yaml2

    yaml_string_1 = """
flags:
  - subdomain-enum

exclude_flags:
  - loud
  - slow

require_flags:
  - passive
  - safe

exclude_modules:
  - certspotter
  - rapiddns

modules:
  - baddns
  - robots

output_modules:
  - csv
  - json

config:
  speculate: False
  excavate: True
"""
    yaml_string_1 = yaml.dump(yaml.safe_load(yaml_string_1), sort_keys=True)
    # preset from yaml
    preset3 = Preset.from_yaml_string(yaml_string_1)
    # yaml to preset
    yaml_string_2 = preset3.to_yaml(sort_keys=True)
    # make sure they're the same
    assert yaml_string_2 == yaml_string_1


def test_preset_cache():
    preset_file = bbot_test_dir / "test_preset.yml"
    yaml_string = """
flags:
  - subdomain-enum

exclude_flags:
  - loud
  - slow
"""
    with open(preset_file, "w") as f:
        f.write(yaml_string)

    preset = Preset.from_yaml_file(preset_file)
    assert "subdomain-enum" in preset.flags
    assert "loud" in preset.exclude_flags
    assert "slow" in preset.exclude_flags
    from bbot.scanner.preset.preset import _preset_cache

    assert preset_file in _preset_cache

    preset_file.unlink()


@pytest.mark.asyncio
async def test_preset_scope(clean_default_config):
    # test target merging
    scan = Scanner("1.2.3.4", preset=Preset.from_dict({"target": ["evilcorp.com"]}))
    await scan._prep()
    assert {str(h) for h in scan.preset.target.seeds.hosts} == {"1.2.3.4/32", "evilcorp.com"}
    assert {e.data for e in scan.target.seeds} == {"1.2.3.4", "evilcorp.com"}
    assert {str(h) for h in scan.target.target.hosts} == {"1.2.3.4/32", "evilcorp.com"}

    blank_preset = Preset()
    blank_preset = blank_preset.validate().bake()
    assert not blank_preset.target.seeds
    assert not blank_preset.target.target
    assert blank_preset.strict_scope is False

    # Positional args define target; seeds must be explicit
    preset1 = Preset(
        "evilcorp.ce",
        seeds=["evilcorp.com", "www.evilcorp.ce"],
        blacklist=["test.www.evilcorp.ce"],
    )
    preset1_baked = preset1.validate().bake()

    # make sure target logic works as expected
    assert "evilcorp.com" in preset1_baked.target.seeds
    assert "evilcorp.com" not in preset1_baked.target.target
    assert "asdf.evilcorp.com" in preset1_baked.target.seeds
    assert "asdf.evilcorp.com" not in preset1_baked.target.target
    assert "asdf.evilcorp.ce" in preset1_baked.target.target
    assert "evilcorp.ce" in preset1_baked.target.target
    assert "test.www.evilcorp.ce" in preset1_baked.blacklist
    assert "evilcorp.ce" not in preset1_baked.blacklist
    assert preset1_baked.in_scope("www.evilcorp.ce")
    assert not preset1_baked.in_scope("evilcorp.com")
    assert not preset1_baked.in_scope("asdf.test.www.evilcorp.ce")

    # test yaml save/load
    yaml1 = preset1.to_yaml(sort_keys=True)
    preset2 = Preset.from_yaml_string(yaml1)
    yaml2 = preset2.to_yaml(sort_keys=True)
    assert yaml1 == yaml2

    # test preset merging
    preset3 = Preset(
        "evilcorp.de",
        seeds=["evilcorp.org"],
        blacklist=["test.www.evilcorp.de"],
        config={"scope": {"strict": True}},
    )

    preset1.merge(preset3)

    preset1_baked = preset1.validate().bake()

    # targets should be merged
    assert "evilcorp.com" in preset1_baked.target.seeds
    assert "www.evilcorp.ce" in preset1_baked.target.seeds
    assert "evilcorp.org" in preset1_baked.target.seeds
    # strict scope is enabled
    assert "asdf.www.evilcorp.ce" not in preset1_baked.target.seeds
    assert "asdf.evilcorp.org" not in preset1_baked.target.seeds
    assert "asdf.evilcorp.com" not in preset1_baked.target.seeds
    assert "asdf.www.evilcorp.ce" not in preset1_baked.target.seeds
    assert "evilcorp.ce" in preset1_baked.target.target
    assert "evilcorp.de" in preset1_baked.target.target
    assert "asdf.evilcorp.de" not in preset1_baked.target.target
    assert "asdf.evilcorp.ce" not in preset1_baked.target.target
    # blacklist should be merged, strict scope does not apply
    assert "test.www.evilcorp.ce" in preset1_baked.blacklist
    assert "test.www.evilcorp.de" in preset1_baked.blacklist
    assert "asdf.test.www.evilcorp.ce" in preset1_baked.blacklist
    assert "asdf.test.www.evilcorp.de" in preset1_baked.blacklist
    assert "asdf.test.www.evilcorp.org" not in preset1_baked.blacklist
    # only the base domain of evilcorp.de should be in scope
    assert not preset1_baked.in_scope("evilcorp.com")
    assert not preset1_baked.in_scope("evilcorp.org")
    assert preset1_baked.in_scope("evilcorp.de")
    assert not preset1_baked.in_scope("asdf.evilcorp.de")
    assert not preset1_baked.in_scope("evilcorp.com")
    assert not preset1_baked.in_scope("asdf.test.www.evilcorp.ce")

    preset4 = Preset(output_modules=["neo4j"])
    preset1.merge(preset4)
    merged_baked = preset1.validate().bake()
    assert "neo4j" in merged_baked.output_modules
    for default in ("csv", "txt", "json"):
        assert default in merged_baked.output_modules

    # test preset merging + seeds/target interaction

    # Domain present as both explicit seed and targets
    preset_domain_with_seed = Preset("evilcorp.com", seeds=["evilcorp.com"], name="domain_with_seed")
    preset_with_target_scope = Preset(
        "1.2.3.4/24",
        "http://evilcorp.net",
        name="with_target_scope",
        seeds=["evilcorp.org"],
        blacklist=["evilcorp.co.uk:443", "bob@evilcorp.co.uk"],
        config={"modules": {"github_workflows": {"api_key": "deadbeef", "output_folder": "asdf"}}},
    )

    preset_domain_with_seed_baked = preset_domain_with_seed.validate().bake()
    preset_with_target_scope_baked = preset_with_target_scope.validate().bake()

    # When seeds and targets are identical, only targets are serialized.
    domain_with_seed_dict = preset_domain_with_seed_baked.to_dict(include_target=True)
    assert domain_with_seed_dict.get("target") == ["evilcorp.com"]
    assert "seeds" not in domain_with_seed_dict

    # preset with explicit target scope
    scope_dict = preset_with_target_scope_baked.to_dict(include_target=True)
    assert set(scope_dict["target"]) == {"1.2.3.0/24", "http://evilcorp.net/"}
    assert set(scope_dict["blacklist"]) == {"bob@evilcorp.co.uk", "evilcorp.co.uk:443"}
    # github_workflows config should be preserved (other module config may also be present)
    assert scope_dict["config"]["modules"]["github_workflows"] == {
        "api_key": "deadbeef",
        "output_folder": "asdf",
    }

    redacted_dict = preset_with_target_scope_baked.to_dict(include_target=True, redact_secrets=True)
    assert set(redacted_dict["target"]) == {"1.2.3.0/24", "http://evilcorp.net/"}
    assert set(redacted_dict["blacklist"]) == {"bob@evilcorp.co.uk", "evilcorp.co.uk:443"}
    assert redacted_dict["config"]["modules"]["github_workflows"] == {"output_folder": "asdf"}

    assert preset_domain_with_seed_baked.in_scope("www.evilcorp.com")
    assert not preset_domain_with_seed_baked.in_scope("www.evilcorp.de")
    assert not preset_domain_with_seed_baked.in_scope("1.2.3.4/24")

    assert "www.evilcorp.org" in preset_with_target_scope_baked.target.seeds
    assert "www.evilcorp.org" not in preset_with_target_scope_baked.target.target
    assert "1.2.3.4" in preset_with_target_scope_baked.target.target
    assert not preset_with_target_scope_baked.in_scope("www.evilcorp.org")
    assert not preset_with_target_scope_baked.in_scope("www.evilcorp.de")
    assert not preset_with_target_scope_baked.in_target("www.evilcorp.org")
    assert not preset_with_target_scope_baked.in_target("www.evilcorp.de")
    assert preset_with_target_scope_baked.in_scope("1.2.3.4")
    assert preset_with_target_scope_baked.in_scope("1.2.3.4/28")
    assert preset_with_target_scope_baked.in_scope("1.2.3.4/24")
    assert preset_with_target_scope_baked.in_target("1.2.3.4")
    assert preset_with_target_scope_baked.in_target("1.2.3.4/28")
    assert preset_with_target_scope_baked.in_target("1.2.3.4/24")

    assert {e.data for e in preset_domain_with_seed_baked.seeds} == {"evilcorp.com"}
    assert {e.data for e in preset_domain_with_seed_baked.target.target} == {"evilcorp.com"}
    assert {e.data for e in preset_with_target_scope_baked.seeds} == {"evilcorp.org"}
    assert {e.data for e in preset_with_target_scope_baked.target.target} == {"1.2.3.0/24", "http://evilcorp.net/"}

    # When merging a preset that has both seeds and target with one that only has
    # target (no explicit seeds), explicit seeds are unioned and targets are unioned.
    preset_domain_with_seed.merge(preset_with_target_scope)
    preset_domain_with_seed_baked = preset_domain_with_seed.validate().bake()
    assert {e.data for e in preset_domain_with_seed_baked.seeds} == {"evilcorp.com", "evilcorp.org"}
    # After merging, target scope should include both the original domain target and the scoped network/URL
    assert {e.data for e in preset_domain_with_seed_baked.target.target} == {
        "evilcorp.com",
        "1.2.3.0/24",
        "http://evilcorp.net/",
    }
    assert "www.evilcorp.org" in preset_domain_with_seed_baked.seeds
    assert "www.evilcorp.com" in preset_domain_with_seed_baked.seeds
    assert "1.2.3.4" in preset_domain_with_seed_baked.target.target
    assert not preset_domain_with_seed_baked.in_scope("www.evilcorp.org")
    # After merging, evilcorp.com remains in target, so its www subdomain is in-scope and in-target
    assert preset_domain_with_seed_baked.in_scope("www.evilcorp.com")
    assert not preset_domain_with_seed_baked.in_target("www.evilcorp.org")
    assert preset_domain_with_seed_baked.in_target("www.evilcorp.com")
    assert preset_domain_with_seed_baked.in_scope("1.2.3.4")

    # When merging a preset that only defines targets (no explicit seeds),
    # its targets are not promoted to seeds in the merged preset, but targets are unioned.
    preset_targets_only = Preset("evilcorp.com")
    preset_with_target_scope = Preset("1.2.3.4/24", seeds=["evilcorp.org"])
    preset_with_target_scope.merge(preset_targets_only)
    preset_with_target_scope_baked = preset_with_target_scope.validate().bake()
    # Seeds stay as the explicit seeds from the base preset
    assert {e.data for e in preset_with_target_scope_baked.seeds} == {"evilcorp.org"}
    # Target scope is the union of both presets' targets.
    assert {e.data for e in preset_with_target_scope_baked.target.target} == {
        "evilcorp.com",
        "1.2.3.0/24",
    }
    # Seed expansion only applies to explicit seeds (evilcorp.org), not merged targets.
    assert "www.evilcorp.org" in preset_with_target_scope_baked.seeds
    assert "www.evilcorp.com" not in preset_with_target_scope_baked.seeds
    # Target expansion only applies to targets (evilcorp.com), not seeds-only domains.
    assert "www.evilcorp.org" not in preset_with_target_scope_baked.target.target
    assert "www.evilcorp.com" in preset_with_target_scope_baked.target.target
    # Scope/target checks reflect that only evilcorp.com is in the merged target.
    assert not preset_with_target_scope_baked.in_scope("www.evilcorp.org")
    assert preset_with_target_scope_baked.in_scope("www.evilcorp.com")
    assert not preset_with_target_scope_baked.in_target("www.evilcorp.org")
    assert preset_with_target_scope_baked.in_target("www.evilcorp.com")
    assert preset_with_target_scope_baked.in_scope("1.2.3.4")

    # Merging two presets created only with positional targets:
    # after bake, each has seeds backfilled from its own target, and merge unions both.
    preset_targets_only1 = Preset("evilcorp.com")
    preset_targets_only2 = Preset("evilcorp.de")
    preset_targets_only1_baked = preset_targets_only1.validate().bake()
    preset_targets_only2_baked = preset_targets_only2.validate().bake()
    assert {e.data for e in preset_targets_only1_baked.seeds} == {"evilcorp.com"}
    assert {e.data for e in preset_targets_only2_baked.seeds} == {"evilcorp.de"}
    assert {e.data for e in preset_targets_only1_baked.target.target} == {"evilcorp.com"}
    assert {e.data for e in preset_targets_only2_baked.target.target} == {"evilcorp.de"}
    preset_targets_only1.merge(preset_targets_only2)
    preset_targets_only1_baked = preset_targets_only1.validate().bake()
    assert {e.data for e in preset_targets_only1_baked.seeds} == {"evilcorp.com", "evilcorp.de"}
    assert {e.data for e in preset_targets_only2_baked.seeds} == {"evilcorp.de"}
    assert {e.data for e in preset_targets_only1_baked.target.target} == {"evilcorp.com", "evilcorp.de"}
    assert {e.data for e in preset_targets_only2_baked.target.target} == {"evilcorp.de"}
    assert "www.evilcorp.com" in preset_targets_only1_baked.seeds
    assert "www.evilcorp.de" in preset_targets_only1_baked.seeds
    assert "www.evilcorp.com" in preset_targets_only1_baked.target.seeds
    assert "www.evilcorp.de" in preset_targets_only1_baked.target.seeds
    assert "www.evilcorp.com" in preset_targets_only1_baked.target.target
    assert "www.evilcorp.de" in preset_targets_only1_baked.target.target
    assert preset_targets_only1_baked.in_target("www.evilcorp.com")
    assert preset_targets_only1_baked.in_target("www.evilcorp.de")
    assert not preset_targets_only1_baked.in_target("1.2.3.4")
    assert preset_targets_only1_baked.in_scope("www.evilcorp.com")
    assert preset_targets_only1_baked.in_scope("www.evilcorp.de")
    assert not preset_targets_only1_baked.in_scope("1.2.3.4")

    preset_targets_only1 = Preset("evilcorp.com")
    preset_targets_only2 = Preset("evilcorp.de")
    preset_targets_only2.merge(preset_targets_only1)
    preset_targets_only1_baked = preset_targets_only1.validate().bake()
    preset_targets_only2_baked = preset_targets_only2.validate().bake()
    assert {e.data for e in preset_targets_only1_baked.seeds} == {"evilcorp.com"}
    assert {e.data for e in preset_targets_only2_baked.seeds} == {"evilcorp.com", "evilcorp.de"}
    assert {e.data for e in preset_targets_only1_baked.target.target} == {"evilcorp.com"}
    assert {e.data for e in preset_targets_only2_baked.target.target} == {"evilcorp.com", "evilcorp.de"}


@pytest.mark.asyncio
async def test_preset_logging():
    scan = Scanner()
    await scan._prep()

    # test individual verbosity levels
    original_log_level = CORE.logger.log_level
    assert original_log_level == logging.DEBUG

    try:
        silent_preset = Preset(silent=True)
        assert silent_preset.silent is True
        assert silent_preset.debug is False
        assert silent_preset.verbose is False
        assert original_log_level == CORE.logger.log_level
        debug_preset = Preset(debug=True)
        assert debug_preset.silent is False
        assert debug_preset.debug is True
        assert debug_preset.verbose is False
        assert original_log_level == CORE.logger.log_level
        verbose_preset = Preset(verbose=True)
        assert verbose_preset.silent is False
        assert verbose_preset.debug is False
        assert verbose_preset.verbose is True
        assert original_log_level == CORE.logger.log_level

        # test conflicting verbosity levels
        silent_and_verbose = Preset(silent=True, verbose=True)
        assert silent_and_verbose.silent is True
        assert silent_and_verbose.debug is False
        assert silent_and_verbose.verbose is True
        baked = silent_and_verbose.validate().bake()
        assert baked.silent is True
        assert baked.debug is False
        assert baked.verbose is False
        assert baked.core.logger.log_level == original_log_level
        baked = silent_and_verbose.validate().bake(scan=scan)
        assert baked.core.logger.log_level == logging.CRITICAL
        assert CORE.logger.log_level == logging.CRITICAL

        CORE.logger.log_level = original_log_level
        assert CORE.logger.log_level == original_log_level

        silent_and_debug = Preset(silent=True, debug=True)
        assert silent_and_debug.silent is True
        assert silent_and_debug.debug is True
        assert silent_and_debug.verbose is False
        baked = silent_and_debug.validate().bake()
        assert baked.silent is True
        assert baked.debug is False
        assert baked.verbose is False
        assert baked.core.logger.log_level == original_log_level
        baked = silent_and_debug.validate().bake(scan=scan)
        assert baked.core.logger.log_level == logging.CRITICAL
        assert CORE.logger.log_level == logging.CRITICAL

        CORE.logger.log_level = original_log_level
        assert CORE.logger.log_level == original_log_level

        debug_and_verbose = Preset(verbose=True, debug=True)
        assert debug_and_verbose.silent is False
        assert debug_and_verbose.debug is True
        assert debug_and_verbose.verbose is True
        baked = debug_and_verbose.validate().bake()
        assert baked.silent is False
        assert baked.debug is True
        assert baked.verbose is False
        assert baked.core.logger.log_level == original_log_level
        baked = debug_and_verbose.validate().bake(scan=scan)
        assert baked.core.logger.log_level == logging.DEBUG
        assert CORE.logger.log_level == logging.DEBUG

        CORE.logger.log_level = original_log_level
        assert CORE.logger.log_level == original_log_level

        all_preset = Preset(verbose=True, debug=True, silent=True)
        assert all_preset.silent is True
        assert all_preset.debug is True
        assert all_preset.verbose is True
        baked = all_preset.validate().bake()
        assert baked.silent is True
        assert baked.debug is False
        assert baked.verbose is False
        assert baked.core.logger.log_level == original_log_level
        baked = all_preset.validate().bake(scan=scan)
        assert baked.core.logger.log_level == logging.CRITICAL
        assert CORE.logger.log_level == logging.CRITICAL

        CORE.logger.log_level = original_log_level
        assert CORE.logger.log_level == original_log_level

        # defaults
        preset = Preset().validate().bake()
        assert preset.core.logger.log_level == original_log_level
        assert CORE.logger.log_level == original_log_level

    finally:
        CORE.logger.log_level = original_log_level
        assert CORE.logger.log_level == original_log_level
        await scan._cleanup()


async def test_preset_module_resolution(clean_default_config):
    preset = Preset().validate().bake()
    sslcert_preloaded = preset.preloaded_module("sslcert")
    wayback_preloaded = preset.preloaded_module("wayback")
    dotnetnuke_preloaded = preset.preloaded_module("dotnetnuke")
    sslcert_flags = sslcert_preloaded.get("flags", [])
    wayback_flags = wayback_preloaded.get("flags", [])
    dotnetnuke_flags = dotnetnuke_preloaded.get("flags", [])
    assert "active" in sslcert_flags
    assert "passive" in wayback_flags
    assert "active" in dotnetnuke_flags
    assert "subdomain-enum" in sslcert_flags
    assert "subdomain-enum" in wayback_flags
    assert "http" in dotnetnuke_preloaded["deps"]["modules"]

    # make sure we have the expected defaults
    assert not preset.scan_modules
    assert set(preset.output_modules) == {"csv", "txt", "json"}
    assert set(preset.internal_modules) == {
        "aggregate",
        "excavate",
        "python",
        "unarchive",
        "speculate",
        "cloudcheck",
        "dnsresolve",
    }
    assert preset.modules == set(preset.output_modules).union(set(preset.internal_modules))

    # make sure dependency resolution works as expected
    preset = Preset(modules=["dotnetnuke"]).validate().bake()
    assert set(preset.scan_modules) == {"dotnetnuke", "http"}

    # make sure flags work as expected
    preset = Preset(flags=["subdomain-enum"]).validate().bake()
    assert preset.flags == {"subdomain-enum"}
    assert "sslcert" in preset.modules
    assert "wayback" in preset.modules
    assert "sslcert" in preset.scan_modules
    assert "wayback" in preset.scan_modules

    # flag + module exclusions
    preset = Preset(flags=["subdomain-enum"], exclude_modules=["sslcert"]).validate().bake()
    assert "sslcert" not in preset.modules
    assert "wayback" in preset.modules
    assert "sslcert" not in preset.scan_modules
    assert "wayback" in preset.scan_modules

    # flag + flag exclusions
    preset = Preset(flags=["subdomain-enum"], exclude_flags=["active"]).validate().bake()
    assert "sslcert" not in preset.modules
    assert "wayback" in preset.modules
    assert "sslcert" not in preset.scan_modules
    assert "wayback" in preset.scan_modules

    # flag + flag requirements
    preset = Preset(flags=["subdomain-enum"], require_flags=["passive"]).validate().bake()
    assert "sslcert" not in preset.modules
    assert "wayback" in preset.modules
    assert "sslcert" not in preset.scan_modules
    assert "wayback" in preset.scan_modules

    # normal module enableement
    preset = Preset(modules=["sslcert", "dotnetnuke", "wayback"]).validate().bake()
    assert set(preset.scan_modules) == {"sslcert", "dotnetnuke", "wayback", "http"}

    # modules + flag exclusions
    preset = Preset(exclude_flags=["active"], modules=["sslcert", "dotnetnuke", "wayback"]).validate().bake()
    assert set(preset.scan_modules) == {"wayback"}

    # modules + flag requirements
    preset = Preset(require_flags=["passive"], modules=["sslcert", "dotnetnuke", "wayback"]).validate().bake()
    assert set(preset.scan_modules) == {"wayback"}

    # modules + module exclusions
    baked_preset = Preset(exclude_modules=["sslcert"], modules=["sslcert", "dotnetnuke", "wayback"]).validate().bake()
    assert baked_preset.modules == {
        "wayback",
        "cloudcheck",
        "python",
        "json",
        "speculate",
        "dnsresolve",
        "aggregate",
        "excavate",
        "unarchive",
        "txt",
        "http",
        "csv",
        "dotnetnuke",
    }


@pytest.mark.asyncio
async def test_custom_module_dir():
    custom_module_dir = bbot_test_dir / "custom_modules"
    custom_module_dir.mkdir(parents=True, exist_ok=True)

    custom_module = custom_module_dir / "testmodule.py"
    with open(custom_module, "w") as f:
        f.write(
            """
from bbot.modules.base import BaseModule

class TestModule(BaseModule):
    watched_events = ["SCAN"]
  
    async def handle_event(self, event):
        await self.emit_event("127.0.0.2", parent=event)
"""
        )

    preset = {
        "module_dirs": [str(custom_module_dir)],
        "modules": ["testmodule"],
    }
    preset = Preset.from_dict(preset)

    scan = Scanner("127.0.0.0/24", preset=preset)
    events = [e async for e in scan.async_start()]
    event_data = [(str(e.data), str(e.module)) for e in events]
    assert ("127.0.0.2", "testmodule") in event_data

    shutil.rmtree(custom_module_dir)


def test_preset_scope_round_trip(clean_default_config):
    preset_dict = {
        # seeds: initial inputs that drive passive modules
        "seeds": ["127.0.0.1"],
        # target: what in_target() / in_scope() check
        "target": ["127.0.0.2"],
        "blacklist": ["127.0.0.3"],
        "config": {"scope": {"strict": True}},
    }
    preset = Preset.from_dict(preset_dict)
    baked = preset.validate().bake()
    # Seeds should round-trip unchanged
    assert list(baked.seeds) == ["127.0.0.1"]
    # Target list should round-trip unchanged
    assert list(baked.target.target.inputs) == ["127.0.0.2"]
    # Blacklist should round-trip unchanged
    assert list(baked.blacklist) == ["127.0.0.3"]
    # Scope config should be preserved
    result = baked.to_dict(include_target=True)
    assert result["config"]["scope"] == preset_dict["config"]["scope"]


def test_preset_target_tolerance():
    # tolerate both "target" and "targets", since this is a common oopsie
    preset_dict = {
        "target": ["127.0.0.1"],
        "targets": ["127.0.0.2"],
    }
    preset = Preset.from_dict(preset_dict)
    baked = preset.validate().bake()
    assert set(baked.seeds) == {"127.0.0.1", "127.0.0.2"}

    preset = Preset.from_yaml_string("""
target:
  - 127.0.0.1
targets:
  - 127.0.0.2
""")
    baked = preset.validate().bake()
    assert set(baked.seeds) == {"127.0.0.1", "127.0.0.2"}


@pytest.mark.asyncio
async def test_preset_module_loader():
    custom_module_dir = bbot_test_dir / "custom_module_dir"
    custom_module_dir_2 = custom_module_dir / "asdf"
    custom_output_module_dir = custom_module_dir / "output"
    custom_internal_module_dir = custom_module_dir / "internal"
    for d in [custom_module_dir, custom_module_dir_2, custom_output_module_dir, custom_internal_module_dir]:
        d.mkdir(parents=True, exist_ok=True)
        assert d.is_dir()
    custom_module_1 = custom_module_dir / "testmodule1.py"
    with open(custom_module_1, "w") as f:
        f.write(
            """
from bbot.modules.base import BaseModule

class TestModule1(BaseModule):
    watched_events = ["URL", "HTTP_RESPONSE"]
    produced_events = ["FINDING"]
"""
        )

    custom_module_2 = custom_output_module_dir / "testmodule2.py"
    with open(custom_module_2, "w") as f:
        f.write(
            """
from bbot.modules.output.base import BaseOutputModule

class TestModule2(BaseOutputModule):
    watched_events = []
"""
        )

    custom_module_3 = custom_internal_module_dir / "testmodule3.py"
    with open(custom_module_3, "w") as f:
        f.write(
            """
from bbot.modules.internal.base import BaseInternalModule

class TestModule3(BaseInternalModule):
    watched_events = []
"""
        )

    custom_module_4 = custom_module_dir_2 / "testmodule4.py"
    with open(custom_module_4, "w") as f:
        f.write(
            """
from bbot.modules.base import BaseModule

class TestModule4(BaseModule):
    watched_events = ["TECHNOLOGY"]
    produced_events = ["FINDING"]
"""
        )

    assert custom_module_1.is_file()
    assert custom_module_2.is_file()
    assert custom_module_3.is_file()
    assert custom_module_4.is_file()

    preset = Preset()
    preset.module_loader.save_preload_cache()
    assert preset.module_loader.preload_cache_file.is_file()

    # at this point, core modules should be loaded, but not custom ones
    assert "baddns" in preset.module_loader.preloaded()
    assert "testmodule1" not in preset.module_loader.preloaded()

    import pickle

    with open(preset.module_loader.preload_cache_file, "rb") as f:
        preloaded = pickle.load(f)
    assert "baddns" in preloaded
    assert "testmodule1" not in preloaded

    # add custom module dir
    preset.module_dirs = [str(custom_module_dir)]
    assert custom_module_dir in preset.module_dirs
    assert custom_module_dir_2 in preset.module_dirs
    assert custom_output_module_dir in preset.module_dirs
    assert custom_internal_module_dir in preset.module_dirs

    # now our custom modules should be loaded
    assert "baddns" in preset.module_loader.preloaded()
    assert "testmodule1" in preset.module_loader.preloaded()
    assert "testmodule2" in preset.module_loader.preloaded()
    assert "testmodule3" in preset.module_loader.preloaded()
    assert "testmodule4" in preset.module_loader.preloaded()

    preset.module_loader.save_preload_cache()
    with open(preset.module_loader.preload_cache_file, "rb") as f:
        preloaded = pickle.load(f)
    assert "baddns" in preloaded
    assert "testmodule1" in preloaded
    assert "testmodule2" in preloaded
    assert "testmodule3" in preloaded
    assert "testmodule4" in preloaded

    # since module loader is shared across all presets, a new preset should now also have our custom modules
    preset2 = Preset()
    assert "baddns" in preset2.module_loader.preloaded()
    assert "testmodule1" in preset2.module_loader.preloaded()
    assert "testmodule2" in preset2.module_loader.preloaded()
    assert "testmodule3" in preset2.module_loader.preloaded()
    assert "testmodule4" in preset2.module_loader.preloaded()

    # reset module_loader
    preset2.module_loader.__init__()

    # custom module dir via preset
    custom_module_dir_3 = bbot_test_dir / "custom_module_dir_3"
    custom_module_dir_3.mkdir(exist_ok=True, parents=True)
    custom_module_5 = custom_module_dir_3 / "testmodule5.py"
    with open(custom_module_5, "w") as f:
        f.write(
            """
from bbot.modules.base import BaseModule

class TestModule5(BaseModule):
    watched_events = ["TECHNOLOGY"]
    produced_events = ["FINDING"]
"""
        )

    # unknown module name is caught at validate()
    with pytest.raises(ValidationError):
        Preset.from_yaml_string(
            """
modules:
  - testmodule5
"""
        ).validate()

    preset = Preset.from_yaml_string(
        f"""
module_dirs:
  - {custom_module_dir_3}
modules:
  - testmodule5
"""
    )
    scan = Scanner(preset=preset)
    await scan._prep()
    assert "testmodule5" in scan.modules


def test_preset_include():
    # test recursive preset inclusion

    custom_preset_dir_1 = bbot_test_dir / "custom_preset_dir"
    custom_preset_dir_2 = custom_preset_dir_1 / "preset_subdir"
    custom_preset_dir_3 = custom_preset_dir_2 / "subsubdir"
    custom_preset_dir_4 = worker_dir("/tmp/.bbot_preset_test")
    custom_preset_dir_5 = custom_preset_dir_4 / "subdir"
    mkdir(custom_preset_dir_1)
    mkdir(custom_preset_dir_2)
    mkdir(custom_preset_dir_3)
    mkdir(custom_preset_dir_4)
    mkdir(custom_preset_dir_5)

    # Real modules so the (now-strict) validator accepts them. We use the
    # universal `module_timeout` field as an opaque marker per preset.
    preset_file = custom_preset_dir_1 / "preset1.yml"
    with open(preset_file, "w") as f:
        f.write(
            """
include:
  - preset2

config:
  modules:
    nuclei:
      module_timeout: 1
"""
        )

    preset_file = custom_preset_dir_2 / "preset2.yml"
    with open(preset_file, "w") as f:
        f.write(
            """
include:
  - preset3

config:
  modules:
    sslcert:
      module_timeout: 2
"""
        )

    preset_file = custom_preset_dir_3 / "preset3.yml"
    with open(preset_file, "w") as f:
        f.write(
            f"""
include:
  # uh oh
  - preset1
  - {custom_preset_dir_4}/preset4

config:
  modules:
    gowitness:
      module_timeout: 3
"""
        )

    preset_file = custom_preset_dir_4 / "preset4.yml"
    with open(preset_file, "w") as f:
        f.write(
            """
include:
  - preset5

config:
  modules:
    robots:
      module_timeout: 4
"""
        )

    preset_file = custom_preset_dir_5 / "preset5.yml"
    with open(preset_file, "w") as f:
        f.write(
            """
config:
  modules:
    wayback:
      module_timeout: 5
"""
        )

    # with include=
    preset = Preset(include=[str(custom_preset_dir_1 / "preset1")])
    assert preset.config["modules"]["nuclei"]["module_timeout"] == 1
    assert preset.config["modules"]["sslcert"]["module_timeout"] == 2
    assert preset.config["modules"]["gowitness"]["module_timeout"] == 3
    assert preset.config["modules"]["robots"]["module_timeout"] == 4
    assert preset.config["modules"]["wayback"]["module_timeout"] == 5

    # same thing but with presets= (an alias to include)
    preset = Preset(presets=[str(custom_preset_dir_1 / "preset1")])
    assert preset.config["modules"]["nuclei"]["module_timeout"] == 1
    assert preset.config["modules"]["sslcert"]["module_timeout"] == 2
    assert preset.config["modules"]["gowitness"]["module_timeout"] == 3
    assert preset.config["modules"]["robots"]["module_timeout"] == 4
    assert preset.config["modules"]["wayback"]["module_timeout"] == 5

    # can't use both include= and presets= at the same time
    with pytest.raises(ValueError):
        preset = Preset(presets=["subdomain-enum"], include=["webbrute"])


@pytest.mark.asyncio
async def test_preset_conditions():
    custom_preset_dir_1 = bbot_test_dir / "custom_preset_dir"
    custom_preset_dir_2 = custom_preset_dir_1 / "preset_subdir"
    mkdir(custom_preset_dir_1)
    mkdir(custom_preset_dir_2)

    preset_file_1 = custom_preset_dir_1 / "preset_condition_1.yml"
    with open(preset_file_1, "w") as f:
        f.write(
            """
include:
  - preset_condition_2
"""
        )

    preset_file_2 = custom_preset_dir_2 / "preset_condition_2.yml"
    with open(preset_file_2, "w") as f:
        f.write(
            """
conditions:
  - |
    {% if config.web.spider_distance == 3 and config.web.spider_depth == 4 %}
      {{ abort("web spider is too aggressive") }}
    {% endif %}
"""
        )

    preset = Preset(include=[preset_file_1])
    assert preset.conditions

    scan = Scanner(preset=preset)
    await scan._prep()
    assert scan.preset.conditions

    await scan._cleanup()

    preset2 = Preset(config={"web": {"spider_distance": 3, "spider_depth": 4}})
    preset.merge(preset2)

    with pytest.raises(PresetAbortError):
        scan = Scanner(preset=preset)
        await scan._prep()


async def test_preset_module_disablement(clean_default_config):
    # internal module disablement
    preset = Preset().validate().bake()
    assert "speculate" in preset.internal_modules
    assert "excavate" in preset.internal_modules
    assert "aggregate" in preset.internal_modules
    preset = Preset(config={"speculate": False}).validate().bake()
    assert "speculate" not in preset.internal_modules
    assert "excavate" in preset.internal_modules
    assert "aggregate" in preset.internal_modules
    preset = Preset(exclude_modules=["speculate", "excavate"]).validate().bake()
    assert "speculate" not in preset.internal_modules
    assert "excavate" not in preset.internal_modules
    assert "aggregate" in preset.internal_modules

    # output module disablement
    preset = Preset().validate().bake()
    assert set(preset.output_modules) == {"txt", "csv", "json"}
    preset = Preset(exclude_modules=["txt", "csv"]).validate().bake()
    assert set(preset.output_modules) == {"json"}
    # output_modules is additive, so specifying json still includes defaults
    preset = Preset(output_modules=["subdomains"]).validate().bake()
    assert set(preset.output_modules) == {"csv", "txt", "json", "subdomains"}


async def test_preset_override(clean_default_config):
    # tests to make sure a preset's config settings override others it includes
    preset_1_yaml = """
name: override1
scan_name: override1
target: ["evilcorp1.com"]
silent: True
modules:
  - robots
config:
  modules:
    robots:
      module_timeout: 10
"""
    preset_2_yaml = """
name: override2
scan_name: override2
target: ["evilcorp2.com"]
debug: true
modules:
  - c99
config:
  modules:
    robots:
      module_timeout: 20
"""
    preset_3_yaml = """
name: override3
scan_name: override3
target: ["evilcorp3.com"]
modules:
  - securitytrails
# test ordering priority
include:
  - override1
  - override2
config:
  web:
    spider_distance: 2
    spider_depth: 3
"""
    preset_4_yaml = """
name: override4
scan_name: override4
target: ["evilcorp4.com"]
modules:
  - virustotal
include:
  - override3
config:
  web:
    spider_distance: 1
    spider_depth: 2
"""
    custom_preset_dir = bbot_test_dir / "custom_preset_dir_override"
    custom_preset_dir.mkdir(parents=True, exist_ok=True)
    preset_1_file = custom_preset_dir / "override1.yml"
    preset_1_file.write_text(preset_1_yaml)
    preset_2_file = custom_preset_dir / "override2.yml"
    preset_2_file.write_text(preset_2_yaml)
    preset_3_file = custom_preset_dir / "override3.yml"
    preset_3_file.write_text(preset_3_yaml)
    preset_4_file = custom_preset_dir / "override4.yml"
    preset_4_file.write_text(preset_4_yaml)

    preset = Preset.from_yaml_file(preset_4_file.resolve())
    assert preset.debug is True
    assert preset.silent is True
    assert preset.name == "override4"
    preset = preset.validate().bake()
    assert preset.debug is False
    assert preset.silent is True
    assert preset.name == "override4"
    assert preset.scan_name == "override4"
    targets = set([str(e.data) for e in preset.target.seeds])
    assert targets == {"evilcorp1.com", "evilcorp2.com", "evilcorp3.com", "evilcorp4.com"}
    assert preset.config["web"]["spider_distance"] == 1
    assert preset.config["web"]["spider_depth"] == 2
    assert preset.config["modules"]["robots"]["module_timeout"] == 20
    assert set(preset.scan_modules) == {"http", "c99", "robots", "virustotal", "securitytrails"}


async def test_preset_require_exclude(clean_default_config):
    def get_module_flags(p):
        for m in p.scan_modules:
            preloaded = p.preloaded_module(m)
            yield m, preloaded.get("flags", [])

    # enable by flag, no exclusions/requirements
    preset = Preset(flags=["subdomain-enum"]).validate().bake()
    assert len(preset.modules) > 25
    module_flags = list(get_module_flags(preset))
    dnsbrute_flags = preset.preloaded_module("dnsbrute").get("flags", [])
    assert "subdomain-enum" in dnsbrute_flags
    assert "active" in dnsbrute_flags
    assert "passive" not in dnsbrute_flags
    assert "loud" in dnsbrute_flags
    assert "safe" not in dnsbrute_flags
    assert "dnsbrute" in [x[0] for x in module_flags]
    assert "certspotter" in [x[0] for x in module_flags]
    assert "c99" in [x[0] for x in module_flags]
    assert any("passive" in flags for module, flags in module_flags)
    assert any("active" in flags for module, flags in module_flags)
    assert any("safe" in flags for module, flags in module_flags)
    assert any("loud" in flags for module, flags in module_flags)

    # enable by flag, one required flag
    preset = Preset(flags=["subdomain-enum"], require_flags=["passive"]).validate().bake()
    assert len(preset.modules) > 25
    module_flags = list(get_module_flags(preset))
    assert "chaos" in [x[0] for x in module_flags]
    assert "http" not in [x[0] for x in module_flags]
    assert all("passive" in flags for module, flags in module_flags)
    assert not any("active" in flags for module, flags in module_flags)
    assert any("safe" in flags for module, flags in module_flags)
    assert any("loud" in flags for module, flags in module_flags)

    # enable by flag, one excluded flag
    preset = Preset(flags=["subdomain-enum"], exclude_flags=["active"]).validate().bake()
    assert len(preset.modules) > 25
    module_flags = list(get_module_flags(preset))
    assert "chaos" in [x[0] for x in module_flags]
    assert "http" not in [x[0] for x in module_flags]
    assert all("passive" in flags for module, flags in module_flags)
    assert not any("active" in flags for module, flags in module_flags)
    assert any("safe" in flags for module, flags in module_flags)
    assert any("loud" in flags for module, flags in module_flags)

    # enable by flag, one excluded module
    preset = Preset(flags=["subdomain-enum"], exclude_modules=["dnsbrute"]).validate().bake()
    assert len(preset.modules) > 25
    module_flags = list(get_module_flags(preset))
    assert "dnsbrute" not in [x[0] for x in module_flags]
    assert "http" in [x[0] for x in module_flags]
    assert any("passive" in flags for module, flags in module_flags)
    assert any("active" in flags for module, flags in module_flags)
    assert any("safe" in flags for module, flags in module_flags)
    assert any("loud" in flags for module, flags in module_flags)

    # enable by flag, multiple required flags
    preset = Preset(flags=["subdomain-enum"], require_flags=["safe", "passive"]).validate().bake()
    assert len(preset.modules) > 20
    module_flags = list(get_module_flags(preset))
    assert "dnsbrute" not in [x[0] for x in module_flags]
    assert all("passive" in flags and "safe" in flags for module, flags in module_flags)
    assert all("active" not in flags and "loud" not in flags for module, flags in module_flags)
    assert not any("active" in flags for module, flags in module_flags)
    assert not any("loud" in flags for module, flags in module_flags)

    # enable by flag, multiple excluded flags
    preset = Preset(flags=["subdomain-enum"], exclude_flags=["loud", "active"]).validate().bake()
    assert len(preset.modules) > 20
    module_flags = list(get_module_flags(preset))
    assert "dnsbrute" not in [x[0] for x in module_flags]
    assert all("passive" in flags and "safe" in flags for module, flags in module_flags)
    assert all("active" not in flags and "loud" not in flags for module, flags in module_flags)
    assert not any("active" in flags for module, flags in module_flags)
    assert not any("loud" in flags for module, flags in module_flags)

    # enable by flag, multiple excluded modules
    preset = Preset(flags=["subdomain-enum"], exclude_modules=["dnsbrute", "c99"]).validate().bake()
    assert len(preset.modules) > 25
    module_flags = list(get_module_flags(preset))
    assert "dnsbrute" not in [x[0] for x in module_flags]
    assert "certspotter" in [x[0] for x in module_flags]
    assert "c99" not in [x[0] for x in module_flags]
    assert any("passive" in flags for module, flags in module_flags)
    assert any("active" in flags for module, flags in module_flags)
    assert any("safe" in flags for module, flags in module_flags)
    assert any("loud" in flags for module, flags in module_flags)


@pytest.mark.asyncio
async def test_preset_output_dir():
    output_dir = bbot_test_dir / "preset_output_dir"
    preset = Preset.from_yaml_string(
        f"""
output_dir: {output_dir}
scan_name: bbot_test
"""
    )
    scan = Scanner(preset=preset)
    await scan.async_start_without_generator()
    scan_dir = output_dir / "bbot_test"
    assert scan_dir.is_dir()
    output_file = scan_dir / "output.txt"
    assert output_file.is_file()

    shutil.rmtree(output_dir, ignore_errors=True)


# regression test for https://github.com/blacklanternsecurity/bbot/issues/2337
async def test_preset_serialization(clean_default_config):
    preset = Preset("192.168.1.1")
    preset = preset.validate().bake()

    import orjson as json

    preset_dict = preset.to_dict(include_target=True)
    print(preset_dict)
    preset_str = json.dumps(preset_dict)
    preset_dict_round_tripped = json.loads(preset_str)
    assert preset_dict_round_tripped == preset_dict
    assert preset_dict["target"] == ["192.168.1.1"]
    assert "seeds" not in preset_dict


def test_preset_yaml_redacts_secrets():
    preset = Preset(
        "evilcorp.com",
        config={"modules": {"github_org": {"api_key": "ghp_secrettoken123"}}},
    )
    preset.validate()
    preset = preset.bake()

    yaml_plain = preset.to_yaml()
    assert "ghp_secrettoken123" in yaml_plain

    yaml_redacted = preset.to_yaml(redact_secrets=True)
    assert "ghp_secrettoken123" not in yaml_redacted
    assert "api_key" not in yaml_redacted


def test_preset_file_targets(tmp_path):
    """Test that file paths in preset target/seeds/blacklist are resolved via PresetPath.

    The preset and its target files live in tmp_path (NOT CWD), so relative paths
    like "targets.txt" can only be found if PresetPath adds the preset's directory
    to its search paths. This is the core behavior being tested.
    """
    import os

    # sanity check: tmp_path is not CWD (otherwise relative resolution is ambiguous)
    assert os.getcwd() != str(tmp_path)

    # create target files next to where the preset will live
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("evilcorp.com\n1.2.3.4\n")
    seeds_file = tmp_path / "seeds.txt"
    seeds_file.write_text("seed1.evilcorp.com\nseed2.evilcorp.com\n")
    blacklist_file = tmp_path / "blacklist.txt"
    blacklist_file.write_text("internal.evilcorp.com\n10.0.0.0/8\n")

    # relative paths: resolved from the preset's directory via PresetPath
    preset_file = tmp_path / "my_preset.yml"
    preset_file.write_text("target:\n  - targets.txt\nseeds:\n  - seeds.txt\nblacklist:\n  - blacklist.txt\n")
    preset = Preset.from_yaml_file(str(preset_file))
    target_inputs = set(preset._target_list)
    assert "evilcorp.com" in target_inputs
    assert "1.2.3.4" in target_inputs
    assert "targets.txt" not in target_inputs
    seed_inputs = set(preset._seeds)
    assert "seed1.evilcorp.com" in seed_inputs
    assert "seed2.evilcorp.com" in seed_inputs
    blacklist_inputs = set(preset._blacklist)
    assert "internal.evilcorp.com" in blacklist_inputs
    assert "10.0.0.0/8" in blacklist_inputs

    # absolute paths for targets, seeds, and blacklist
    preset_file2 = tmp_path / "my_preset2.yml"
    preset_file2.write_text(
        f"target:\n  - {targets_file}\nseeds:\n  - {seeds_file}\nblacklist:\n  - {blacklist_file}\n"
    )
    preset2 = Preset.from_yaml_file(str(preset_file2))
    target_inputs2 = set(preset2._target_list)
    assert "evilcorp.com" in target_inputs2
    assert "1.2.3.4" in target_inputs2
    seed_inputs2 = set(preset2._seeds)
    assert "seed1.evilcorp.com" in seed_inputs2
    assert "seed2.evilcorp.com" in seed_inputs2
    blacklist_inputs2 = set(preset2._blacklist)
    assert "internal.evilcorp.com" in blacklist_inputs2
    assert "10.0.0.0/8" in blacklist_inputs2

    # mixed: file paths + literal targets
    preset_file3 = tmp_path / "my_preset3.yml"
    preset_file3.write_text("target:\n  - targets.txt\n  - extra.evilcorp.com\n")
    preset3 = Preset.from_yaml_file(str(preset_file3))
    target_inputs3 = set(preset3._target_list)
    assert "evilcorp.com" in target_inputs3
    assert "1.2.3.4" in target_inputs3
    assert "extra.evilcorp.com" in target_inputs3

    # non-existent file strings are kept as literal targets
    preset4 = Preset.from_dict({"target": ["not_a_file.txt", "192.168.1.1"]})
    target_inputs4 = set(preset4._target_list)
    assert "not_a_file.txt" in target_inputs4
    assert "192.168.1.1" in target_inputs4

    # subdirectory: preset in a nested dir references a file in the same nested dir
    subdir = tmp_path / "nested" / "presets"
    subdir.mkdir(parents=True)
    nested_targets = subdir / "my_targets.txt"
    nested_targets.write_text("nested.evilcorp.com\n")
    nested_preset = subdir / "nested_preset.yml"
    nested_preset.write_text("target:\n  - my_targets.txt\n")
    preset5 = Preset.from_yaml_file(str(nested_preset))
    target_inputs5 = set(preset5._target_list)
    assert "nested.evilcorp.com" in target_inputs5
    assert "my_targets.txt" not in target_inputs5


def test_preset_dnsresolve_required_by_dns_name_consumers():
    # gate must fire for all three opt-out paths when any DNS_NAME-watching module is enabled
    for opt_out in (
        {"exclude_modules": ["dnsresolve"], "flags": ["subdomain-enum"]},
        {"config": {"dnsresolve": False}, "flags": ["subdomain-enum"]},
        {"config": {"dns": {"disable": True}}, "flags": ["subdomain-enum"]},
    ):
        with pytest.raises(ValidationError, match="dnsresolve is required"):
            Preset(**opt_out).validate().bake()

    # dns.minimal keeps dnsresolve in the pipeline -- must NOT fire
    Preset(flags=["subdomain-enum"], config={"dns": {"minimal": True}}).validate().bake()

    # disabling dnsresolve with no DNS_NAME consumers enabled is allowed
    Preset(exclude_modules=["dnsresolve"]).validate().bake()


def test_preset_path_no_clobber_default(tmp_path):
    """Regression: loading a preset via path (e.g. ./scan.yml) must not clobber
    the default preset search path, even when the preset lives in a parent
    directory of bbot/presets/. Previously, add_path() would remove
    DEFAULT_PRESET_PATH from the search list, causing rglob to search the
    entire tree and match non-YAML files (like .venv/bin/baddns).
    """
    from bbot.scanner.preset.path import PresetPath, DEFAULT_PRESET_PATH

    # preset that includes a built-in preset by name (no extension, no path)
    preset_file = tmp_path / "scan.yml"
    preset_file.write_text("description: regression test\ninclude:\n  - baddns\n")

    # non-YAML decoy that would match an extensionless rglob for "baddns"
    decoy_dir = tmp_path / "fake_venv" / "bin"
    decoy_dir.mkdir(parents=True)
    decoy = decoy_dir / "baddns"
    decoy.write_text("#!/usr/bin/env python\nif __name__ == '__main__':\n    pass\n")

    pp = PresetPath()
    # resolve the top-level file
    found = pp.find(str(preset_file))
    assert found == preset_file.resolve()
    # DEFAULT_PRESET_PATH must survive
    assert DEFAULT_PRESET_PATH in pp.paths

    # the built-in include must resolve to the real preset, not the decoy
    found_include = pp.find("baddns")
    assert found_include.suffix in (".yml", ".yaml")
    assert "fake_venv" not in str(found_include)

    # full round-trip through Preset
    preset = Preset.from_yaml_file(str(preset_file))
    assert "baddns" in preset.explicit_scan_modules


def test_malformed_yaml_preset_file(tmp_path):
    """Regression test for https://github.com/blacklanternsecurity/bbot/issues/3158

    Malformed YAML (e.g. bad indentation) must raise a clear ValidationError,
    not an unhandled exception with a raw traceback.
    """
    malformed = tmp_path / "bad_preset.yml"
    malformed.write_text(
        "target:\n  - evilcorp.com\nmodules:\n  sslcert:\n    option: value\n   robots:\n    option: value\n"
    )
    with pytest.raises(ValidationError, match="YAML syntax error"):
        Preset.from_yaml_file(str(malformed))


def test_malformed_yaml_preset_string():
    """Regression test for https://github.com/blacklanternsecurity/bbot/issues/3158

    Malformed YAML string must raise ValidationError, not an unhandled yaml.YAMLError.
    """
    malformed_yaml = "target:\n  - evilcorp.com\nconfig:\n  key: value\n   bad_indent: oops\n"
    with pytest.raises(ValidationError, match="YAML syntax error"):
        Preset.from_yaml_string(malformed_yaml)


def test_malformed_yaml_config_file(tmp_path):
    """Regression test for https://github.com/blacklanternsecurity/bbot/issues/3158

    Malformed YAML in a config file (bbot.yml / secrets.yml) must raise
    ConfigLoadError with a helpful message, not crash with a raw traceback.
    """
    from bbot.core.config.files import BBOTConfigFiles
    from bbot.errors import ConfigLoadError

    malformed = tmp_path / "bad_config.yml"
    malformed.write_text("web:\n  http_rate_limit: 100\n   bad_key: value\n")
    with pytest.raises(ConfigLoadError, match="YAML syntax error"):
        BBOTConfigFiles._get_config(None, str(malformed))


def test_all_presets_ignores_non_preset_yaml(tmp_path):
    """Regression test for https://github.com/blacklanternsecurity/bbot/issues/3189

    When -p loads a preset from an arbitrary directory (e.g. $HOME), that
    directory must NOT be searched by all_presets / -lp. Otherwise every
    .yml file under it (Ansible collections, CI configs, etc.) is parsed
    and produces warning spam.
    """
    import bbot.scanner.preset.preset as preset_mod
    from bbot.scanner.preset.path import PresetPath

    # create a valid preset in tmp_path (simulates ~/my_preset.yml)
    preset_file = tmp_path / "my_preset.yml"
    preset_file.write_text("description: test preset\nmodules:\n  - sslcert\n")

    # create non-preset yaml files nearby (simulates Ansible, CI, etc.)
    junk_dir = tmp_path / "ansible"
    junk_dir.mkdir()
    (junk_dir / "playbook.yml").write_text("hosts: all\ntasks: []\n")
    (tmp_path / "ci.yml").write_text("on: push\njobs: {}\n")

    # save and replace global state so we get a clean PRESET_PATH
    orig_preset_path = preset_mod.PRESET_PATH
    orig_default_presets = preset_mod.DEFAULT_PRESETS
    try:
        fresh_path = PresetPath()
        preset_mod.PRESET_PATH = fresh_path
        # also patch the path module's reference
        import bbot.scanner.preset.path as path_mod

        orig_path_singleton = path_mod.PRESET_PATH
        path_mod.PRESET_PATH = fresh_path

        # simulate -p /tmp/xxx/my_preset.yml: find() adds tmp_path to search paths
        found = fresh_path.find(str(preset_file))
        assert found == preset_file.resolve()
        # tmp_path is now in search paths (needed for include resolution)
        assert tmp_path.resolve() in fresh_path.paths

        # reset the cached presets so all_presets re-enumerates
        preset_mod.DEFAULT_PRESETS = None

        preset = Preset()

        # collect warnings emitted during all_presets enumeration
        import logging

        warnings = []
        handler = logging.Handler()
        handler.emit = lambda record: (
            warnings.append(record.getMessage()) if record.levelno >= logging.WARNING else None
        )
        preset_logger = logging.getLogger("bbot.presets")
        preset_logger.addHandler(handler)
        try:
            preset.all_presets
        finally:
            preset_logger.removeHandler(handler)

        # no warnings should reference the junk files from tmp_path
        junk_warnings = [w for w in warnings if "playbook.yml" in w or "ci.yml" in w]
        assert not junk_warnings, f"all_presets tried to parse non-preset YAML files: {junk_warnings}"
    finally:
        preset_mod.DEFAULT_PRESETS = orig_default_presets
        preset_mod.PRESET_PATH = orig_preset_path
        path_mod.PRESET_PATH = orig_path_singleton


def test_config_isolated_during_tests():
    # the suite must never resolve to the user's real ~/.config/bbot
    from bbot.core import CORE

    config_dir = CORE.files_config.config_dir
    real_config_dir = (Path.home() / ".config" / "bbot").resolve()
    assert config_dir != real_config_dir
    assert str(config_dir).startswith(str(Path(tempfile.gettempdir()).resolve()))


def test_config_reset(tmp_path, monkeypatch):
    from bbot.core import CORE
    from bbot.core.modules import MODULE_LOADER

    files = CORE.files_config
    monkeypatch.setattr(files, "config_dir", tmp_path)
    monkeypatch.setattr(files, "config_filename", tmp_path / "bbot.yml")
    monkeypatch.setattr(files, "secrets_filename", tmp_path / "secrets.yml")
    config_file = tmp_path / "bbot.yml"
    secrets_file = tmp_path / "secrets.yml"

    # first run: files don't exist -> generated as commented templates
    MODULE_LOADER.ensure_config_files()
    assert config_file.is_file() and secrets_file.is_file()
    # secrets.yml is owner-only from the start
    assert stat.S_IMODE(secrets_file.stat().st_mode) == 0o600

    # resetting "config" backs up the existing file and must not touch
    # secrets.yml (where API keys live)
    config_file.write_text("scope:\n  strict: false\n")
    secrets_before = secrets_file.read_text()
    backups = MODULE_LOADER.reset_config_files(["config"])
    assert set(backups) == {tmp_path / "bbot.yml.bak"}
    assert (tmp_path / "bbot.yml.bak").read_text() == "scope:\n  strict: false\n"
    assert secrets_file.read_text() == secrets_before
    # the regenerated file is a fresh commented template
    assert "# NOTICE" in config_file.read_text()

    # a backup of a hardened secrets.yml keeps its tightened permissions
    secrets_file.chmod(0o400)
    backups = MODULE_LOADER.reset_config_files(["secrets"])
    assert set(backups) == {tmp_path / "secrets.yml.bak"}
    assert stat.S_IMODE((tmp_path / "secrets.yml.bak").stat().st_mode) == 0o400
    # the regenerated secrets.yml is still owner-only
    assert stat.S_IMODE(secrets_file.stat().st_mode) & 0o077 == 0

    # a second reset must not clobber the first backup
    backups2 = MODULE_LOADER.reset_config_files(["secrets"])
    assert set(backups2) == {tmp_path / "secrets.yml.bak.1"}
    assert (tmp_path / "secrets.yml.bak").is_file()


def test_config_reset_both(tmp_path, monkeypatch):
    from bbot.core import CORE
    from bbot.core.modules import MODULE_LOADER

    files = CORE.files_config
    monkeypatch.setattr(files, "config_dir", tmp_path)
    monkeypatch.setattr(files, "config_filename", tmp_path / "bbot.yml")
    monkeypatch.setattr(files, "secrets_filename", tmp_path / "secrets.yml")
    config_file = tmp_path / "bbot.yml"

    MODULE_LOADER.ensure_config_files()

    # reset both at once -> both backed up
    backups = MODULE_LOADER.reset_config_files(["config", "secrets"])
    assert {b.name for b in backups} == {"bbot.yml.bak", "secrets.yml.bak"}

    # resetting only "secrets" leaves bbot.yml untouched
    config_before = config_file.read_text()
    backups = MODULE_LOADER.reset_config_files(["secrets"])
    assert set(backups) == {tmp_path / "secrets.yml.bak.1"}
    assert config_file.read_text() == config_before


def test_config_secret_file_permissions(tmp_path):
    from bbot.core.modules import MODULE_LOADER

    target = tmp_path / "secrets.yml"

    # a brand-new secret file is owner-only, never world/group readable
    MODULE_LOADER._write_secret_text(target, "secret a")
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert target.read_text() == "secret a"

    # the user hardened it further -> rewrite preserves the tighter perms
    target.chmod(0o400)
    MODULE_LOADER._write_secret_text(target, "secret b")
    assert stat.S_IMODE(target.stat().st_mode) == 0o400
    assert target.read_text() == "secret b"

    # an existing file with loose perms -> tightened back to owner-only
    target.chmod(0o644)
    MODULE_LOADER._write_secret_text(target, "secret c")
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert target.read_text() == "secret c"


def test_config_secret_file_refuses_insecure(tmp_path, monkeypatch):
    from bbot.core.modules import MODULE_LOADER
    from bbot.errors import BBOTError

    target = tmp_path / "secrets.yml"

    # simulate a filesystem where we can't restrict permissions: the secret is
    # not written, and no temp file is left behind
    real_fchmod = os.fchmod
    monkeypatch.setattr(os, "fchmod", lambda fd, mode: real_fchmod(fd, 0o644))
    with pytest.raises(BBOTError, match="could not restrict permissions"):
        MODULE_LOADER._write_secret_text(target, "secret stuff")
    assert not target.exists()
    assert list(tmp_path.glob(".secrets.yml.*")) == []
