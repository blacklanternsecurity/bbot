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
    for yaml_file, (loaded_preset, category, preset_path, original_filename) in preset.all_presets.items():
        assert (
            loaded_preset.description
        ), f'Preset "{loaded_preset.name}" at {original_filename} does not have a description.'


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
        strict_scope=False,
    )
    assert "evilcorp.com" in preset1.target
    assert "evilcorp.ce" in preset1.whitelist
    assert "test.www.evilcorp.ce" in preset1.blacklist
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
    assert "evilcorp.ce" in preset1.whitelist
    assert "evilcorp.de" in preset1.whitelist
    assert not "asdf.evilcorp.de" in preset1.whitelist
    assert not "asdf.evilcorp.ce" in preset1.whitelist
    # blacklist should be merged, strict scope does not apply
    assert "asdf.test.www.evilcorp.ce" in preset1.blacklist
    assert "asdf.test.www.evilcorp.de" in preset1.blacklist
    assert not "asdf.test.www.evilcorp.org" in preset1.blacklist
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
    original_log_level = preset.core.logger.log_level
    try:
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
    finally:
        preset.core.logger.log_level = original_log_level


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
    pass
"""
        )

    custom_module_3 = custom_internal_module_dir / "testmodule3.py"
    with open(custom_module_3, "w") as f:
        f.write(
            """
from bbot.modules.internal.base import BaseInternalModule

class TestModule3(BaseInternalModule):
    pass
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

    preset = Preset(include=[str(custom_preset_dir_1 / "preset1")])
    assert preset.config.modules.testpreset1.test == "asdf"
    assert preset.config.modules.testpreset2.test == "fdsa"
    assert preset.config.modules.testpreset3.test == "qwerty"
    assert preset.config.modules.testpreset4.test == "zxcv"
    assert preset.config.modules.testpreset5.test == "hjkl"


def test_preset_conditions():
    custom_preset_dir_1 = bbot_test_dir / "custom_preset_dir"
    custom_preset_dir_2 = custom_preset_dir_1 / "preset_subdir"
    mkdir(custom_preset_dir_1)
    mkdir(custom_preset_dir_2)

    preset_file_1 = custom_preset_dir_1 / "preset1.yml"
    with open(preset_file_1, "w") as f:
        f.write(
            """
include:
  - preset2
"""
        )

    preset_file_2 = custom_preset_dir_2 / "preset2.yml"
    with open(preset_file_2, "w") as f:
        f.write(
            """
conditions:
  - |
    {% if config.web_spider_distance == 3 and config.web_spider_depth == 4 %}
      {{ abort("web spider is too aggressive") }}
    {% endif %}
"""
        )

    preset = Preset(include=[preset_file_1])
    assert preset.conditions

    scan = Scanner(preset=preset)
    assert scan.preset.conditions

    preset2 = Preset(config={"web_spider_distance": 3, "web_spider_depth": 4})
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
    assert set(preset.output_modules) == {"python", "human", "csv", "json"}
    preset = Preset(exclude_modules=["human", "csv"]).bake()
    assert set(preset.output_modules) == {"python", "json"}
    preset = Preset(output_modules=["json"]).bake()
    assert set(preset.output_modules) == {"json"}


def test_preset_require_exclude():

    def get_module_flags(p):
        for m in p.scan_modules:
            preloaded = p.preloaded_module(m)
            yield m, preloaded.get("flags", [])

    # enable by flag, no exclusions/requirements
    preset = Preset(flags=["subdomain-enum"])
    assert len(preset.modules) > 25
    module_flags = list(get_module_flags(preset))
    massdns_flags = preset.preloaded_module("massdns").get("flags", [])
    assert "subdomain-enum" in massdns_flags
    assert "passive" in massdns_flags
    assert not "active" in massdns_flags
    assert "aggressive" in massdns_flags
    assert not "safe" in massdns_flags
    assert "massdns" in [x[0] for x in module_flags]
    assert "certspotter" in [x[0] for x in module_flags]
    assert "c99" in [x[0] for x in module_flags]
    assert any("passive" in flags for module, flags in module_flags)
    assert any("active" in flags for module, flags in module_flags)
    assert any("safe" in flags for module, flags in module_flags)
    assert any("aggressive" in flags for module, flags in module_flags)

    # enable by flag, one required flag
    preset = Preset(flags=["subdomain-enum"], require_flags=["passive"])
    assert len(preset.modules) > 25
    module_flags = list(get_module_flags(preset))
    assert "massdns" in [x[0] for x in module_flags]
    assert all("passive" in flags for module, flags in module_flags)
    assert not any("active" in flags for module, flags in module_flags)
    assert any("safe" in flags for module, flags in module_flags)
    assert any("aggressive" in flags for module, flags in module_flags)

    # enable by flag, one excluded flag
    preset = Preset(flags=["subdomain-enum"], exclude_flags=["active"])
    assert len(preset.modules) > 25
    module_flags = list(get_module_flags(preset))
    assert "massdns" in [x[0] for x in module_flags]
    assert all("passive" in flags for module, flags in module_flags)
    assert not any("active" in flags for module, flags in module_flags)
    assert any("safe" in flags for module, flags in module_flags)
    assert any("aggressive" in flags for module, flags in module_flags)

    # enable by flag, one excluded module
    preset = Preset(flags=["subdomain-enum"], exclude_modules=["massdns"])
    assert len(preset.modules) > 25
    module_flags = list(get_module_flags(preset))
    assert not "massdns" in [x[0] for x in module_flags]
    assert any("passive" in flags for module, flags in module_flags)
    assert any("active" in flags for module, flags in module_flags)
    assert any("safe" in flags for module, flags in module_flags)
    assert any("aggressive" in flags for module, flags in module_flags)

    # enable by flag, multiple required flags
    preset = Preset(flags=["subdomain-enum"], require_flags=["safe", "passive"])
    assert len(preset.modules) > 25
    module_flags = list(get_module_flags(preset))
    assert not "massdns" in [x[0] for x in module_flags]
    assert all("passive" in flags and "safe" in flags for module, flags in module_flags)
    assert all("active" not in flags and "aggressive" not in flags for module, flags in module_flags)
    assert not any("active" in flags for module, flags in module_flags)
    assert not any("aggressive" in flags for module, flags in module_flags)

    # enable by flag, multiple excluded flags
    preset = Preset(flags=["subdomain-enum"], exclude_flags=["aggressive", "active"])
    assert len(preset.modules) > 25
    module_flags = list(get_module_flags(preset))
    assert not "massdns" in [x[0] for x in module_flags]
    assert all("passive" in flags and "safe" in flags for module, flags in module_flags)
    assert all("active" not in flags and "aggressive" not in flags for module, flags in module_flags)
    assert not any("active" in flags for module, flags in module_flags)
    assert not any("aggressive" in flags for module, flags in module_flags)

    # enable by flag, multiple excluded modules
    preset = Preset(flags=["subdomain-enum"], exclude_modules=["massdns", "c99"])
    assert len(preset.modules) > 25
    module_flags = list(get_module_flags(preset))
    assert not "massdns" in [x[0] for x in module_flags]
    assert "certspotter" in [x[0] for x in module_flags]
    assert not "c99" in [x[0] for x in module_flags]
    assert any("passive" in flags for module, flags in module_flags)
    assert any("active" in flags for module, flags in module_flags)
    assert any("safe" in flags for module, flags in module_flags)
    assert any("aggressive" in flags for module, flags in module_flags)
