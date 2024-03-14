from ..bbot_fixtures import *  # noqa F401

from bbot.scanner import Preset


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


def test_preset_yaml():

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
        strict_scope=False,
    )
    assert "evilcorp.com" in preset1.target
    assert "evilcorp.ce" in preset1.whitelist
    assert "test.www.evilcorp.ce" in preset1.blacklist
    assert "sslcert" in preset1.scan_modules

    # test yaml save/load
    yaml1 = preset1.to_yaml(sort_keys=True)
    preset2 = Preset.from_yaml_string(yaml1)
    yaml2 = preset2.to_yaml(sort_keys=True)
    assert yaml1 == yaml2


def test_preset_scope():

    blank_preset = Preset()
    assert not blank_preset.target
    assert blank_preset.strict_scope == False

    preset1 = Preset(
        "evilcorp.com",
        "www.evilcorp.ce",
        whitelist=["evilcorp.ce"],
        blacklist=["test.www.evilcorp.ce"],
    )

    # make sure target logic works as expected
    assert "evilcorp.com" in preset1.target
    assert "asdf.evilcorp.com" in preset1.target
    assert "asdf.www.evilcorp.ce" in preset1.target
    assert not "evilcorp.ce" in preset1.target
    assert "evilcorp.ce" in preset1.whitelist
    assert "test.www.evilcorp.ce" in preset1.blacklist
    assert not "evilcorp.ce" in preset1.blacklist
    assert preset1.in_scope("www.evilcorp.ce")
    assert not preset1.in_scope("evilcorp.com")
    assert not preset1.in_scope("asdf.test.www.evilcorp.ce")

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
        strict_scope=True,
    )

    preset1.merge(preset3)

    # targets should be merged
    assert "evilcorp.com" in preset1.target
    assert "www.evilcorp.ce" in preset1.target
    assert "evilcorp.org" in preset1.target
    # strict scope is enabled
    assert not "asdf.evilcorp.com" in preset1.target
    assert not "asdf.www.evilcorp.ce" in preset1.target
    # whitelist is overridden, not merged
    assert not "evilcorp.ce" in preset1.whitelist
    assert "evilcorp.de" in preset1.whitelist
    assert not "asdf.evilcorp.de" in preset1.whitelist
    # blacklist should be merged, strict scope does not apply
    assert "asdf.test.www.evilcorp.ce" in preset1.blacklist
    assert "asdf.test.www.evilcorp.de" in preset1.blacklist
    # only the base domain of evilcorp.de should be in scope
    assert not preset1.in_scope("evilcorp.com")
    assert not preset1.in_scope("evilcorp.org")
    assert preset1.in_scope("evilcorp.de")
    assert not preset1.in_scope("asdf.evilcorp.de")
    assert not preset1.in_scope("evilcorp.com")
    assert not preset1.in_scope("asdf.test.www.evilcorp.ce")

    preset4 = Preset(output_modules="neo4j")
    set(preset1.output_modules) == {"python", "csv", "human", "json"}
    preset1.merge(preset4)
    set(preset1.output_modules) == {"python", "csv", "human", "json", "neo4j"}


def test_preset_logging():
    # test verbosity levels (conflicting verbose/debug/silent)
    preset = Preset(verbose=True)
    assert preset.verbose == True
    assert preset.debug == False
    assert preset.silent == False
    assert preset.core.logger.log_level == logging.VERBOSE
    preset.debug = True
    assert preset.verbose == False
    assert preset.debug == True
    assert preset.silent == False
    assert preset.core.logger.log_level == logging.DEBUG
    preset.silent = True
    assert preset.verbose == False
    assert preset.debug == False
    assert preset.silent == True
    assert preset.core.logger.log_level == logging.CRITICAL


def test_preset_module_resolution():
    preset = Preset()
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
    assert set(preset.output_modules) == {"python", "csv", "human", "json"}
    assert set(preset.internal_modules) == {"aggregate", "excavate", "speculate"}
    assert preset.modules == set(preset.output_modules).union(set(preset.internal_modules))

    # make sure dependency resolution works as expected
    preset.modules = ["wappalyzer"]
    assert set(preset.scan_modules) == {"wappalyzer", "httpx"}

    # make sure flags work as expected
    preset = Preset()
    assert not preset.flags
    assert not preset.scan_modules
    preset.flags = ["subdomain-enum"]
    assert "sslcert" in preset.modules
    assert "wayback" in preset.modules
    assert "sslcert" in preset.scan_modules
    assert "wayback" in preset.scan_modules

    # make sure module exclusions work as expected
    preset.exclude_modules = ["sslcert"]
    assert "sslcert" not in preset.modules
    assert "wayback" in preset.modules
    assert "sslcert" not in preset.scan_modules
    assert "wayback" in preset.scan_modules
    preset.scan_modules = ["sslcert"]
    assert "sslcert" not in preset.modules
    assert "wayback" not in preset.modules
    assert "sslcert" not in preset.scan_modules
    assert "wayback" not in preset.scan_modules
    preset.exclude_modules = []
    preset.scan_modules = ["sslcert"]
    assert "sslcert" in preset.modules
    assert "wayback" not in preset.modules
    assert "sslcert" in preset.scan_modules
    assert "wayback" not in preset.scan_modules
    preset.add_module("wayback")
    assert "sslcert" in preset.modules
    assert "wayback" in preset.modules
    assert "sslcert" in preset.scan_modules
    assert "wayback" in preset.scan_modules
    preset.exclude_modules = ["sslcert"]
    assert "sslcert" not in preset.modules
    assert "wayback" in preset.modules
    assert "sslcert" not in preset.scan_modules
    assert "wayback" in preset.scan_modules

    # make sure flag requirements work as expected
    preset = Preset()
    preset.require_flags = ["passive"]
    preset.scan_modules = ["sslcert"]
    assert not preset.scan_modules
    preset.scan_modules = ["wappalyzer"]
    assert not preset.scan_modules
    preset.flags = ["subdomain-enum"]
    assert "wayback" in preset.modules
    assert "wayback" in preset.scan_modules
    assert "sslcert" not in preset.modules
    assert "sslcert" not in preset.scan_modules
    preset.require_flags = []
    assert "wayback" in preset.modules
    assert "wayback" in preset.scan_modules
    assert "sslcert" not in preset.modules
    assert "sslcert" not in preset.scan_modules
    assert not preset.require_flags
    preset.flags = []
    preset.scan_modules = []
    assert not preset.flags
    assert not preset.scan_modules
    preset.scan_modules = ["sslcert", "wayback"]
    assert "wayback" in preset.modules
    assert "wayback" in preset.scan_modules
    assert "sslcert" in preset.modules
    assert "sslcert" in preset.scan_modules
    preset.require_flags = ["passive"]
    assert "wayback" in preset.modules
    assert "wayback" in preset.scan_modules
    assert "sslcert" not in preset.modules
    assert "sslcert" not in preset.scan_modules

    # make sure flag exclusions work as expected
    preset = Preset()
    preset.exclude_flags = ["active"]
    preset.scan_modules = ["sslcert"]
    assert not preset.scan_modules
    preset.scan_modules = ["wappalyzer"]
    assert not preset.scan_modules
    preset.flags = ["subdomain-enum"]
    assert "wayback" in preset.modules
    assert "wayback" in preset.scan_modules
    assert "sslcert" not in preset.modules
    assert "sslcert" not in preset.scan_modules
    preset.exclude_flags = []
    assert "wayback" in preset.modules
    assert "wayback" in preset.scan_modules
    assert "sslcert" not in preset.modules
    assert "sslcert" not in preset.scan_modules
    assert not preset.require_flags
    preset.flags = []
    preset.scan_modules = []
    assert not preset.flags
    assert not preset.scan_modules
    preset.scan_modules = ["sslcert", "wayback"]
    assert "wayback" in preset.modules
    assert "wayback" in preset.scan_modules
    assert "sslcert" in preset.modules
    assert "sslcert" in preset.scan_modules
    preset.exclude_flags = ["active"]
    assert "wayback" in preset.modules
    assert "wayback" in preset.scan_modules
    assert "sslcert" not in preset.modules
    assert "sslcert" not in preset.scan_modules


def test_preset_module_loader():
    # preset = Preset()
    # ensure custom module dir works
    # ensure default configs are refreshed
    # ensure find-and-replace happens
    # ensure


# test recursive include


# test custom module load directory
#  make sure it works with cli arg module/flag/config syntax validation
