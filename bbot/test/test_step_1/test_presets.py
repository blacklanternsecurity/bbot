from ..bbot_fixtures import *  # noqa F401

from bbot.scanner import Preset


def test_presets():

    blank_preset = Preset()
    assert not blank_preset.target
    assert blank_preset.strict_scope == False

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
        strict_scope=True,
    )

    # test yaml save/load
    yaml1 = preset1.to_yaml(sort_keys=True)
    preset2 = Preset.from_yaml(yaml1)
    yaml2 = preset2.to_yaml(sort_keys=True)
    assert yaml1 == yaml2

    # test preset merging
    # preset3 = Preset(
    #     "evilcorp.org",
    #     whitelist=["evilcorp.ce"],
    #     blacklist=["test.www.evilcorp.ce"],
    #     modules=["sslcert"],
    #     output_modules=["json"],
    #     exclude_modules=["ipneighbor"],
    #     flags=["subdomain-enum"],
    #     require_flags=["safe"],
    #     exclude_flags=["slow"],
    #     verbose=False,
    #     debug=False,
    #     silent=True,
    #     config={"preset_test_asdf": 1},
    #     strict_scope=True,
    # )

    # test config merging

    # make sure custom / default split works as expected

    # test preset merging

    # test verbosity levels (conflicting verbose/debug/silent)

    # test custom module load directory
    #  make sure it works with cli arg module/flag/config syntax validation

    # test yaml save/load, make sure it's the same
