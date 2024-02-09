def test_presets():
    from bbot.core import CORE

    assert "module_paths" in CORE.config
    assert CORE.module_loader.module_paths
    assert any(str(x).endswith("/modules") for x in CORE.module_loader.module_paths)
    assert "HTTP_RESPONSE" in CORE.config.omit_event_types

    # make sure .copy() works as intended
    # preset_copy = CORE.copy()
    # assert isinstance(preset_copy, CORE.__class__)
    # base_tests(CORE)
    # base_tests(preset_copy)
    # preset_copy.update({"asdf": {"fdsa": "1234"}})
    # assert "asdf" in preset_copy
    # assert preset_copy.asdf.fdsa == "1234"
    # assert not "asdf" in CORE

    # preset_copy["testing"] = {"test1": "value"}
    # assert "testing" in preset_copy
    # assert "testing" not in CORE
