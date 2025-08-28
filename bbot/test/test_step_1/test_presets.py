from ..bbot_fixtures import *  # noqa F401

from bbot.scanner import Scanner, Preset


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

    import omegaconf

    assert "testasdf" not in CORE.default_config
    assert "testasdf" not in CORE.custom_config
    assert "testasdf" not in CORE.config

    core_copy = CORE.copy()
    # make sure our default config is read-only
    with pytest.raises(omegaconf.errors.ReadonlyConfigError):
        core_copy.default_config["testasdf"] = "test"
    # same for merged config
    with pytest.raises(omegaconf.errors.ReadonlyConfigError):
        core_copy.config["testasdf"] = "test"

    assert "testasdf" not in core_copy.default_config
    assert "testasdf" not in core_copy.custom_config
    assert "testasdf" not in core_copy.config

    core_copy.custom_config["testasdf"] = "test"
    assert "testasdf" not in core_copy.default_config
    assert "testasdf" in core_copy.custom_config
    assert "testasdf" in core_copy.config

    # test config merging
    config_to_merge = omegaconf.OmegaConf.create({"test123": {"test321": [3, 2, 1], "test456": [4, 5, 6]}})
    core_copy.merge_custom(config_to_merge)
    assert "test123" not in core_copy.default_config
    assert "test123" in core_copy.custom_config
    assert "test123" in core_copy.config
    assert "test321" in core_copy.custom_config["test123"]
    assert "test321" in core_copy.config["test123"]

    # test deletion
    del core_copy.custom_config.test123.test321
    assert "test123" in core_copy.custom_config
    assert "test123" in core_copy.config
    assert "test321" not in core_copy.custom_config["test123"]
    assert "test321" not in core_copy.config["test123"]
    assert "test456" in core_copy.custom_config["test123"]
    assert "test456" in core_copy.config["test123"]


def test_preset_yaml(clean_default_config):
    import yaml

    preset1 = Preset(
        "evilcorp.com",
        "www.evilcorp.ce",
        whitelist=["evilcorp.ce"],
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
        config={"preset_test_asdf": 1},
    )
    preset1 = preset1.bake()
    assert "evilcorp.com" in preset1.target.seeds
    assert "evilcorp.ce" not in preset1.target.seeds
    assert "asdf.www.evilcorp.ce" in preset1.target.seeds
    assert "evilcorp.ce" in preset1.whitelist
    assert "asdf.evilcorp.ce" in preset1.whitelist
    assert "test.www.evilcorp.ce" in preset1.blacklist
    assert "asdf.test.www.evilcorp.ce" in preset1.blacklist
    assert "sslcert" in preset1.scan_modules
    assert preset1.whitelisted("evilcorp.ce")
    assert preset1.whitelisted("www.evilcorp.ce")
    assert not preset1.whitelisted("evilcorp.com")
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
  - aggressive
  - slow

require_flags:
  - passive
  - safe

exclude_modules:
  - certspotter
  - rapiddns

modules:
  - robots
  - wappalyzer

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
  - aggressive
  - slow
"""
    with open(preset_file, "w") as f:
        f.write(yaml_string)

    preset = Preset.from_yaml_file(preset_file)
    assert "subdomain-enum" in preset.flags
    assert "aggressive" in preset.exclude_flags
    assert "slow" in preset.exclude_flags
    from bbot.scanner.preset.preset import _preset_cache

    assert preset_file in _preset_cache

    preset_file.unlink()


def test_preset_scope():
    # test target merging
    scan = Scanner("1.2.3.4", preset=Preset.from_dict({"target": ["evilcorp.com"]}))
    assert {str(h) for h in scan.preset.target.seeds.hosts} == {"1.2.3.4/32", "evilcorp.com"}
    assert {e.data for e in scan.target.seeds} == {"1.2.3.4", "evilcorp.com"}
    assert {e.data for e in scan.target.whitelist} == {"1.2.3.4/32", "evilcorp.com"}

    blank_preset = Preset()
    blank_preset = blank_preset.bake()
    assert not blank_preset.target.seeds
    assert not blank_preset.target.whitelist
    assert blank_preset.strict_scope is False

    preset1 = Preset(
        "evilcorp.com",
        "www.evilcorp.ce",
        whitelist=["evilcorp.ce"],
        blacklist=["test.www.evilcorp.ce"],
    )
    preset1_baked = preset1.bake()

    # make sure target logic works as expected
    assert "evilcorp.com" in preset1_baked.target.seeds
    assert "evilcorp.com" not in preset1_baked.target.whitelist
    assert "asdf.evilcorp.com" in preset1_baked.target.seeds
    assert "asdf.evilcorp.com" not in preset1_baked.target.whitelist
    assert "asdf.evilcorp.ce" in preset1_baked.whitelist
    assert "evilcorp.ce" in preset1_baked.whitelist
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
        "evilcorp.org",
        whitelist=["evilcorp.de"],
        blacklist=["test.www.evilcorp.de"],
        config={"scope": {"strict": True}},
    )

    preset1.merge(preset3)

    preset1_baked = preset1.bake()

    # targets should be merged
    assert "evilcorp.com" in preset1_baked.target.seeds
    assert "www.evilcorp.ce" in preset1_baked.target.seeds
    assert "evilcorp.org" in preset1_baked.target.seeds
    # strict scope is enabled
    assert "asdf.www.evilcorp.ce" not in preset1_baked.target.seeds
    assert "asdf.evilcorp.org" not in preset1_baked.target.seeds
    assert "asdf.evilcorp.com" not in preset1_baked.target.seeds
    assert "asdf.www.evilcorp.ce" not in preset1_baked.target.seeds
    assert "evilcorp.ce" in preset1_baked.whitelist
    assert "evilcorp.de" in preset1_baked.whitelist
    assert "asdf.evilcorp.de" not in preset1_baked.whitelist
    assert "asdf.evilcorp.ce" not in preset1_baked.whitelist
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

    preset4 = Preset(output_modules="neo4j")
    set(preset1.output_modules) == {"python", "csv", "txt", "json", "stdout"}
    preset1.merge(preset4)
    set(preset1.output_modules) == {"python", "csv", "txt", "json", "stdout", "neo4j"}

    # test preset merging + whitelist

    preset_nowhitelist = Preset("evilcorp.com", name="nowhitelist")
    preset_whitelist = Preset(
        "evilcorp.org",
        name="whitelist",
        whitelist=["1.2.3.4/24", "http://evilcorp.net"],
        blacklist=["evilcorp.co.uk:443", "bob@evilcorp.co.uk"],
        config={"modules": {"secretsdb": {"api_key": "deadbeef", "otherthing": "asdf"}}},
    )

    preset_nowhitelist_baked = preset_nowhitelist.bake()
    preset_whitelist_baked = preset_whitelist.bake()

    assert preset_nowhitelist_baked.to_dict(include_target=True) == {
        "target": ["evilcorp.com"],
    }
    assert preset_whitelist_baked.to_dict(include_target=True) == {
        "target": ["evilcorp.org"],
        "whitelist": ["1.2.3.0/24", "http://evilcorp.net/"],
        "blacklist": ["bob@evilcorp.co.uk", "evilcorp.co.uk:443"],
        "config": {"modules": {"secretsdb": {"api_key": "deadbeef", "otherthing": "asdf"}}},
    }
    assert preset_whitelist_baked.to_dict(include_target=True, redact_secrets=True) == {
        "target": ["evilcorp.org"],
        "whitelist": ["1.2.3.0/24", "http://evilcorp.net/"],
        "blacklist": ["bob@evilcorp.co.uk", "evilcorp.co.uk:443"],
        "config": {"modules": {"secretsdb": {"otherthing": "asdf"}}},
    }

    assert preset_nowhitelist_baked.in_scope("www.evilcorp.com")
    assert not preset_nowhitelist_baked.in_scope("www.evilcorp.de")
    assert not preset_nowhitelist_baked.in_scope("1.2.3.4/24")

    assert "www.evilcorp.org" in preset_whitelist_baked.target.seeds
    assert "www.evilcorp.org" not in preset_whitelist_baked.target.whitelist
    assert "1.2.3.4" in preset_whitelist_baked.whitelist
    assert not preset_whitelist_baked.in_scope("www.evilcorp.org")
    assert not preset_whitelist_baked.in_scope("www.evilcorp.de")
    assert not preset_whitelist_baked.whitelisted("www.evilcorp.org")
    assert not preset_whitelist_baked.whitelisted("www.evilcorp.de")
    assert preset_whitelist_baked.in_scope("1.2.3.4")
    assert preset_whitelist_baked.in_scope("1.2.3.4/28")
    assert preset_whitelist_baked.in_scope("1.2.3.4/24")
    assert preset_whitelist_baked.whitelisted("1.2.3.4")
    assert preset_whitelist_baked.whitelisted("1.2.3.4/28")
    assert preset_whitelist_baked.whitelisted("1.2.3.4/24")

    assert {e.data for e in preset_nowhitelist_baked.seeds} == {"evilcorp.com"}
    assert {e.data for e in preset_nowhitelist_baked.whitelist} == {"evilcorp.com"}
    assert {e.data for e in preset_whitelist_baked.seeds} == {"evilcorp.org"}
    assert {e.data for e in preset_whitelist_baked.whitelist} == {"1.2.3.0/24", "http://evilcorp.net/"}

    preset_nowhitelist.merge(preset_whitelist)
    preset_nowhitelist_baked = preset_nowhitelist.bake()
    assert {e.data for e in preset_nowhitelist_baked.seeds} == {"evilcorp.com", "evilcorp.org"}
    assert {e.data for e in preset_nowhitelist_baked.whitelist} == {"1.2.3.0/24", "http://evilcorp.net/"}
    assert "www.evilcorp.org" in preset_nowhitelist_baked.seeds
    assert "www.evilcorp.com" in preset_nowhitelist_baked.seeds
    assert "1.2.3.4" in preset_nowhitelist_baked.whitelist
    assert not preset_nowhitelist_baked.in_scope("www.evilcorp.org")
    assert not preset_nowhitelist_baked.in_scope("www.evilcorp.com")
    assert not preset_nowhitelist_baked.whitelisted("www.evilcorp.org")
    assert not preset_nowhitelist_baked.whitelisted("www.evilcorp.com")
    assert preset_nowhitelist_baked.in_scope("1.2.3.4")

    preset_nowhitelist = Preset("evilcorp.com")
    preset_whitelist = Preset("evilcorp.org", whitelist=["1.2.3.4/24"])
    preset_whitelist.merge(preset_nowhitelist)
    preset_whitelist_baked = preset_whitelist.bake()
    assert {e.data for e in preset_whitelist_baked.seeds} == {"evilcorp.com", "evilcorp.org"}
    assert {e.data for e in preset_whitelist_baked.whitelist} == {"1.2.3.0/24"}
    assert "www.evilcorp.org" in preset_whitelist_baked.seeds
    assert "www.evilcorp.com" in preset_whitelist_baked.seeds
    assert "www.evilcorp.org" not in preset_whitelist_baked.target.whitelist
    assert "www.evilcorp.com" not in preset_whitelist_baked.target.whitelist
    assert "1.2.3.4" in preset_whitelist_baked.whitelist
    assert not preset_whitelist_baked.in_scope("www.evilcorp.org")
    assert not preset_whitelist_baked.in_scope("www.evilcorp.com")
    assert not preset_whitelist_baked.whitelisted("www.evilcorp.org")
    assert not preset_whitelist_baked.whitelisted("www.evilcorp.com")
    assert preset_whitelist_baked.in_scope("1.2.3.4")

    preset_nowhitelist1 = Preset("evilcorp.com")
    preset_nowhitelist2 = Preset("evilcorp.de")
    preset_nowhitelist1_baked = preset_nowhitelist1.bake()
    preset_nowhitelist2_baked = preset_nowhitelist2.bake()
    assert {e.data for e in preset_nowhitelist1_baked.seeds} == {"evilcorp.com"}
    assert {e.data for e in preset_nowhitelist2_baked.seeds} == {"evilcorp.de"}
    assert {e.data for e in preset_nowhitelist1_baked.whitelist} == {"evilcorp.com"}
    assert {e.data for e in preset_nowhitelist2_baked.whitelist} == {"evilcorp.de"}
    preset_nowhitelist1.merge(preset_nowhitelist2)
    preset_nowhitelist1_baked = preset_nowhitelist1.bake()
    assert {e.data for e in preset_nowhitelist1_baked.seeds} == {"evilcorp.com", "evilcorp.de"}
    assert {e.data for e in preset_nowhitelist2_baked.seeds} == {"evilcorp.de"}
    assert {e.data for e in preset_nowhitelist1_baked.whitelist} == {"evilcorp.com", "evilcorp.de"}
    assert {e.data for e in preset_nowhitelist2_baked.whitelist} == {"evilcorp.de"}
    assert "www.evilcorp.com" in preset_nowhitelist1_baked.seeds
    assert "www.evilcorp.de" in preset_nowhitelist1_baked.seeds
    assert "www.evilcorp.com" in preset_nowhitelist1_baked.target.seeds
    assert "www.evilcorp.de" in preset_nowhitelist1_baked.target.seeds
    assert "www.evilcorp.com" in preset_nowhitelist1_baked.whitelist
    assert "www.evilcorp.de" in preset_nowhitelist1_baked.whitelist
    assert preset_nowhitelist1_baked.whitelisted("www.evilcorp.com")
    assert preset_nowhitelist1_baked.whitelisted("www.evilcorp.de")
    assert not preset_nowhitelist1_baked.whitelisted("1.2.3.4")
    assert preset_nowhitelist1_baked.in_scope("www.evilcorp.com")
    assert preset_nowhitelist1_baked.in_scope("www.evilcorp.de")
    assert not preset_nowhitelist1_baked.in_scope("1.2.3.4")

    preset_nowhitelist1 = Preset("evilcorp.com")
    preset_nowhitelist2 = Preset("evilcorp.de")
    preset_nowhitelist2.merge(preset_nowhitelist1)
    preset_nowhitelist1_baked = preset_nowhitelist1.bake()
    preset_nowhitelist2_baked = preset_nowhitelist2.bake()
    assert {e.data for e in preset_nowhitelist1_baked.seeds} == {"evilcorp.com"}
    assert {e.data for e in preset_nowhitelist2_baked.seeds} == {"evilcorp.com", "evilcorp.de"}
    assert {e.data for e in preset_nowhitelist1_baked.whitelist} == {"evilcorp.com"}
    assert {e.data for e in preset_nowhitelist2_baked.whitelist} == {"evilcorp.com", "evilcorp.de"}


@pytest.mark.asyncio
async def test_preset_logging():
    scan = Scanner()

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
        baked = silent_and_verbose.bake()
        assert baked.silent is True
        assert baked.debug is False
        assert baked.verbose is False
        assert baked.core.logger.log_level == original_log_level
        baked = silent_and_verbose.bake(scan=scan)
        assert baked.core.logger.log_level == logging.CRITICAL
        assert CORE.logger.log_level == logging.CRITICAL

        CORE.logger.log_level = original_log_level
        assert CORE.logger.log_level == original_log_level

        silent_and_debug = Preset(silent=True, debug=True)
        assert silent_and_debug.silent is True
        assert silent_and_debug.debug is True
        assert silent_and_debug.verbose is False
        baked = silent_and_debug.bake()
        assert baked.silent is True
        assert baked.debug is False
        assert baked.verbose is False
        assert baked.core.logger.log_level == original_log_level
        baked = silent_and_debug.bake(scan=scan)
        assert baked.core.logger.log_level == logging.CRITICAL
        assert CORE.logger.log_level == logging.CRITICAL

        CORE.logger.log_level = original_log_level
        assert CORE.logger.log_level == original_log_level

        debug_and_verbose = Preset(verbose=True, debug=True)
        assert debug_and_verbose.silent is False
        assert debug_and_verbose.debug is True
        assert debug_and_verbose.verbose is True
        baked = debug_and_verbose.bake()
        assert baked.silent is False
        assert baked.debug is True
        assert baked.verbose is False
        assert baked.core.logger.log_level == original_log_level
        baked = debug_and_verbose.bake(scan=scan)
        assert baked.core.logger.log_level == logging.DEBUG
        assert CORE.logger.log_level == logging.DEBUG

        CORE.logger.log_level = original_log_level
        assert CORE.logger.log_level == original_log_level

        all_preset = Preset(verbose=True, debug=True, silent=True)
        assert all_preset.silent is True
        assert all_preset.debug is True
        assert all_preset.verbose is True
        baked = all_preset.bake()
        assert baked.silent is True
        assert baked.debug is False
        assert baked.verbose is False
        assert baked.core.logger.log_level == original_log_level
        baked = all_preset.bake(scan=scan)
        assert baked.core.logger.log_level == logging.CRITICAL
        assert CORE.logger.log_level == logging.CRITICAL

        CORE.logger.log_level = original_log_level
        assert CORE.logger.log_level == original_log_level

        # defaults
        preset = Preset().bake()
        assert preset.core.logger.log_level == original_log_level
        assert CORE.logger.log_level == original_log_level

    finally:
        CORE.logger.log_level = original_log_level
        assert CORE.logger.log_level == original_log_level
        await scan._cleanup()


def test_preset_module_resolution(clean_default_config):
    preset = Preset().bake()
    sslcert_preloaded = preset.preloaded_module("sslcert")
    wayback_preloaded = preset.preloaded_module("wayback")
    wappalyzer_preloaded = preset.preloaded_module("wappalyzer")
    sslcert_flags = sslcert_preloaded.get("flags", [])
    wayback_flags = wayback_preloaded.get("flags", [])
    wappalyzer_flags = wappalyzer_preloaded.get("flags", [])
    assert "active" in sslcert_flags
    assert "passive" in wayback_flags
    assert "active" in wappalyzer_flags
    assert "subdomain-enum" in sslcert_flags
    assert "subdomain-enum" in wayback_flags
    assert "httpx" in wappalyzer_preloaded["deps"]["modules"]

    # make sure we have the expected defaults
    assert not preset.scan_modules
    assert set(preset.output_modules) == {"python", "csv", "txt", "json"}
    assert set(preset.internal_modules) == {
        "aggregate",
        "excavate",
        "unarchive",
        "speculate",
        "cloudcheck",
        "dnsresolve",
    }
    assert preset.modules == set(preset.output_modules).union(set(preset.internal_modules))

    # make sure dependency resolution works as expected
    preset = Preset(modules=["wappalyzer"]).bake()
    assert set(preset.scan_modules) == {"wappalyzer", "httpx"}

    # make sure flags work as expected
    preset = Preset(flags=["subdomain-enum"]).bake()
    assert preset.flags == {"subdomain-enum"}
    assert "sslcert" in preset.modules
    assert "wayback" in preset.modules
    assert "sslcert" in preset.scan_modules
    assert "wayback" in preset.scan_modules

    # flag + module exclusions
    preset = Preset(flags=["subdomain-enum"], exclude_modules=["sslcert"]).bake()
    assert "sslcert" not in preset.modules
    assert "wayback" in preset.modules
    assert "sslcert" not in preset.scan_modules
    assert "wayback" in preset.scan_modules

    # flag + flag exclusions
    preset = Preset(flags=["subdomain-enum"], exclude_flags=["active"]).bake()
    assert "sslcert" not in preset.modules
    assert "wayback" in preset.modules
    assert "sslcert" not in preset.scan_modules
    assert "wayback" in preset.scan_modules

    # flag + flag requirements
    preset = Preset(flags=["subdomain-enum"], require_flags=["passive"]).bake()
    assert "sslcert" not in preset.modules
    assert "wayback" in preset.modules
    assert "sslcert" not in preset.scan_modules
    assert "wayback" in preset.scan_modules

    # normal module enableement
    preset = Preset(modules=["sslcert", "wappalyzer", "wayback"]).bake()
    assert set(preset.scan_modules) == {"sslcert", "wappalyzer", "wayback", "httpx"}

    # modules + flag exclusions
    preset = Preset(exclude_flags=["active"], modules=["sslcert", "wappalyzer", "wayback"]).bake()
    assert set(preset.scan_modules) == {"wayback"}

    # modules + flag requirements
    preset = Preset(require_flags=["passive"], modules=["sslcert", "wappalyzer", "wayback"]).bake()
    assert set(preset.scan_modules) == {"wayback"}

    # modules + module exclusions
    preset = Preset(exclude_modules=["sslcert"], modules=["sslcert", "wappalyzer", "wayback"]).bake()
    baked_preset = preset.bake()
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
        "httpx",
        "csv",
        "wappalyzer",
    }


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
    produced_events = ["VULNERABILITY"]
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
    assert "wappalyzer" in preset.module_loader.preloaded()
    assert "testmodule1" not in preset.module_loader.preloaded()

    import pickle

    with open(preset.module_loader.preload_cache_file, "rb") as f:
        preloaded = pickle.load(f)
    assert "wappalyzer" in preloaded
    assert "testmodule1" not in preloaded

    # add custom module dir
    preset.module_dirs = [str(custom_module_dir)]
    assert custom_module_dir in preset.module_dirs
    assert custom_module_dir_2 in preset.module_dirs
    assert custom_output_module_dir in preset.module_dirs
    assert custom_internal_module_dir in preset.module_dirs

    # now our custom modules should be loaded
    assert "wappalyzer" in preset.module_loader.preloaded()
    assert "testmodule1" in preset.module_loader.preloaded()
    assert "testmodule2" in preset.module_loader.preloaded()
    assert "testmodule3" in preset.module_loader.preloaded()
    assert "testmodule4" in preset.module_loader.preloaded()

    preset.module_loader.save_preload_cache()
    with open(preset.module_loader.preload_cache_file, "rb") as f:
        preloaded = pickle.load(f)
    assert "wappalyzer" in preloaded
    assert "testmodule1" in preloaded
    assert "testmodule2" in preloaded
    assert "testmodule3" in preloaded
    assert "testmodule4" in preloaded

    # since module loader is shared across all presets, a new preset should now also have our custom modules
    preset2 = Preset()
    assert "wappalyzer" in preset2.module_loader.preloaded()
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

    preset = Preset.from_yaml_string(
        """
modules:
  - testmodule5
"""
    )
    # should fail
    with pytest.raises(ValidationError):
        scan = Scanner(preset=preset)

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
    custom_preset_dir_4 = Path("/tmp/.bbot_preset_test")
    custom_preset_dir_5 = custom_preset_dir_4 / "subdir"
    mkdir(custom_preset_dir_1)
    mkdir(custom_preset_dir_2)
    mkdir(custom_preset_dir_3)
    mkdir(custom_preset_dir_4)
    mkdir(custom_preset_dir_5)

    preset_file = custom_preset_dir_1 / "preset1.yml"
    with open(preset_file, "w") as f:
        f.write(
            """
include:
  - preset2

config:
  modules:
    testpreset1:
      test: asdf
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
    testpreset2:
      test: fdsa
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
    testpreset3:
      test: qwerty
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
    testpreset4:
      test: zxcv
"""
        )

    preset_file = custom_preset_dir_5 / "preset5.yml"
    with open(preset_file, "w") as f:
        f.write(
            """
config:
  modules:
    testpreset5:
      test: hjkl
"""
        )

    # with include=
    preset = Preset(include=[str(custom_preset_dir_1 / "preset1")])
    assert preset.config.modules.testpreset1.test == "asdf"
    assert preset.config.modules.testpreset2.test == "fdsa"
    assert preset.config.modules.testpreset3.test == "qwerty"
    assert preset.config.modules.testpreset4.test == "zxcv"
    assert preset.config.modules.testpreset5.test == "hjkl"

    # same thing but with presets= (an alias to include)
    preset = Preset(presets=[str(custom_preset_dir_1 / "preset1")])
    assert preset.config.modules.testpreset1.test == "asdf"
    assert preset.config.modules.testpreset2.test == "fdsa"
    assert preset.config.modules.testpreset3.test == "qwerty"
    assert preset.config.modules.testpreset4.test == "zxcv"
    assert preset.config.modules.testpreset5.test == "hjkl"

    # can't use both include= and presets= at the same time
    with pytest.raises(ValueError):
        preset = Preset(presets=["subdomain-enum"], include=["dirbust-light"])


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
    assert scan.preset.conditions

    await scan._cleanup()

    preset2 = Preset(config={"web": {"spider_distance": 3, "spider_depth": 4}})
    preset.merge(preset2)

    with pytest.raises(PresetAbortError):
        Scanner(preset=preset)


def test_preset_module_disablement(clean_default_config):
    # internal module disablement
    preset = Preset().bake()
    assert "speculate" in preset.internal_modules
    assert "excavate" in preset.internal_modules
    assert "aggregate" in preset.internal_modules
    preset = Preset(config={"speculate": False}).bake()
    assert "speculate" not in preset.internal_modules
    assert "excavate" in preset.internal_modules
    assert "aggregate" in preset.internal_modules
    preset = Preset(exclude_modules=["speculate", "excavate"]).bake()
    assert "speculate" not in preset.internal_modules
    assert "excavate" not in preset.internal_modules
    assert "aggregate" in preset.internal_modules

    # internal module disablement
    preset = Preset().bake()
    assert set(preset.output_modules) == {"python", "txt", "csv", "json"}
    preset = Preset(exclude_modules=["txt", "csv"]).bake()
    assert set(preset.output_modules) == {"python", "json"}
    preset = Preset(output_modules=["json"]).bake()
    assert set(preset.output_modules) == {"json"}


def test_preset_override():
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
    asdf:
      option1: asdf
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
    asdf:
      option1: fdsa
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
    preset = preset.bake()
    assert preset.debug is False
    assert preset.silent is True
    assert preset.name == "override4"
    assert preset.scan_name == "override4"
    targets = set([str(e.data) for e in preset.target.seeds])
    assert targets == {"evilcorp1.com", "evilcorp2.com", "evilcorp3.com", "evilcorp4.com"}
    assert preset.config["web"]["spider_distance"] == 1
    assert preset.config["web"]["spider_depth"] == 2
    assert preset.config["modules"]["asdf"]["option1"] == "fdsa"
    assert set(preset.scan_modules) == {"httpx", "c99", "robots", "virustotal", "securitytrails"}


def test_preset_require_exclude():
    def get_module_flags(p):
        for m in p.scan_modules:
            preloaded = p.preloaded_module(m)
            yield m, preloaded.get("flags", [])

    # enable by flag, no exclusions/requirements
    preset = Preset(flags=["subdomain-enum"]).bake()
    assert len(preset.modules) > 25
    module_flags = list(get_module_flags(preset))
    dnsbrute_flags = preset.preloaded_module("dnsbrute").get("flags", [])
    assert "subdomain-enum" in dnsbrute_flags
    assert "active" in dnsbrute_flags
    assert "passive" not in dnsbrute_flags
    assert "aggressive" in dnsbrute_flags
    assert "safe" not in dnsbrute_flags
    assert "dnsbrute" in [x[0] for x in module_flags]
    assert "certspotter" in [x[0] for x in module_flags]
    assert "c99" in [x[0] for x in module_flags]
    assert any("passive" in flags for module, flags in module_flags)
    assert any("active" in flags for module, flags in module_flags)
    assert any("safe" in flags for module, flags in module_flags)
    assert any("aggressive" in flags for module, flags in module_flags)

    # enable by flag, one required flag
    preset = Preset(flags=["subdomain-enum"], require_flags=["passive"]).bake()
    assert len(preset.modules) > 25
    module_flags = list(get_module_flags(preset))
    assert "chaos" in [x[0] for x in module_flags]
    assert "httpx" not in [x[0] for x in module_flags]
    assert all("passive" in flags for module, flags in module_flags)
    assert not any("active" in flags for module, flags in module_flags)
    assert any("safe" in flags for module, flags in module_flags)
    assert any("aggressive" in flags for module, flags in module_flags)

    # enable by flag, one excluded flag
    preset = Preset(flags=["subdomain-enum"], exclude_flags=["active"]).bake()
    assert len(preset.modules) > 25
    module_flags = list(get_module_flags(preset))
    assert "chaos" in [x[0] for x in module_flags]
    assert "httpx" not in [x[0] for x in module_flags]
    assert all("passive" in flags for module, flags in module_flags)
    assert not any("active" in flags for module, flags in module_flags)
    assert any("safe" in flags for module, flags in module_flags)
    assert any("aggressive" in flags for module, flags in module_flags)

    # enable by flag, one excluded module
    preset = Preset(flags=["subdomain-enum"], exclude_modules=["dnsbrute"]).bake()
    assert len(preset.modules) > 25
    module_flags = list(get_module_flags(preset))
    assert "dnsbrute" not in [x[0] for x in module_flags]
    assert "httpx" in [x[0] for x in module_flags]
    assert any("passive" in flags for module, flags in module_flags)
    assert any("active" in flags for module, flags in module_flags)
    assert any("safe" in flags for module, flags in module_flags)
    assert any("aggressive" in flags for module, flags in module_flags)

    # enable by flag, multiple required flags
    preset = Preset(flags=["subdomain-enum"], require_flags=["safe", "passive"]).bake()
    assert len(preset.modules) > 25
    module_flags = list(get_module_flags(preset))
    assert "dnsbrute" not in [x[0] for x in module_flags]
    assert all("passive" in flags and "safe" in flags for module, flags in module_flags)
    assert all("active" not in flags and "aggressive" not in flags for module, flags in module_flags)
    assert not any("active" in flags for module, flags in module_flags)
    assert not any("aggressive" in flags for module, flags in module_flags)

    # enable by flag, multiple excluded flags
    preset = Preset(flags=["subdomain-enum"], exclude_flags=["aggressive", "active"]).bake()
    assert len(preset.modules) > 25
    module_flags = list(get_module_flags(preset))
    assert "dnsbrute" not in [x[0] for x in module_flags]
    assert all("passive" in flags and "safe" in flags for module, flags in module_flags)
    assert all("active" not in flags and "aggressive" not in flags for module, flags in module_flags)
    assert not any("active" in flags for module, flags in module_flags)
    assert not any("aggressive" in flags for module, flags in module_flags)

    # enable by flag, multiple excluded modules
    preset = Preset(flags=["subdomain-enum"], exclude_modules=["dnsbrute", "c99"]).bake()
    assert len(preset.modules) > 25
    module_flags = list(get_module_flags(preset))
    assert "dnsbrute" not in [x[0] for x in module_flags]
    assert "certspotter" in [x[0] for x in module_flags]
    assert "c99" not in [x[0] for x in module_flags]
    assert any("passive" in flags for module, flags in module_flags)
    assert any("active" in flags for module, flags in module_flags)
    assert any("safe" in flags for module, flags in module_flags)
    assert any("aggressive" in flags for module, flags in module_flags)


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
def test_preset_serialization():
    preset = Preset("192.168.1.1")
    preset = preset.bake()

    import orjson as json

    preset_dict = preset.to_dict(include_target=True)
    print(preset_dict)
    preset_str = json.dumps(preset_dict)
    preset_dict = json.loads(preset_str)
    assert preset_dict == {"target": ["192.168.1.1"], "whitelist": ["192.168.1.1/32"]}
