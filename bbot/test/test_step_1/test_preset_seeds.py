from bbot.scanner.preset import Preset


def test_preset_target_and_seeds_default():
    """
    If no explicit seeds are provided, seeds should be copied from target.
    """
    preset = Preset("evilcorp.com")
    baked = preset.bake()

    target = baked.target
    assert set(target.target.inputs) == {"evilcorp.com"}
    assert set(target.seeds.inputs) == {"evilcorp.com"}


def test_preset_target_and_seeds_explicit_seeds_override():
    """
    If explicit seeds are provided, they should NOT be copied from target.
    """
    preset = Preset("evilcorp.com", seeds=["seedonly.evilcorp.com"])
    baked = preset.bake()

    target = baked.target
    assert set(target.target.inputs) == {"evilcorp.com"}
    assert set(target.seeds.inputs) == {"seedonly.evilcorp.com"}
