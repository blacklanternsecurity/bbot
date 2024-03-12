from ..bbot_fixtures import *  # noqa F401

from bbot.scanner import Preset


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
    preset2 = Preset.from_yaml(yaml1)
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
    preset2 = Preset.from_yaml(yaml1)
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

    # test config merging

    # make sure custom / default split works as expected

    # test preset merging

    # test verbosity levels (conflicting verbose/debug/silent)

    # test custom module load directory
    #  make sure it works with cli arg module/flag/config syntax validation
