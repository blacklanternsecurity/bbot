from ..bbot_fixtures import *  # noqa: F401


def test_config(bbot_config, bbot_scanner):
    scan1 = bbot_scanner("127.0.0.1", modules=["ipneighbor", "speculate"], config=bbot_config)
    scan1.load_modules()
    assert scan1.config.plumbus == "asdf"
    assert scan1.modules["ipneighbor"].config.test_option == "ipneighbor"
    assert scan1.modules["python"].config.test_option == "asdf"
    assert scan1.modules["speculate"].config.test_option == "speculate"
