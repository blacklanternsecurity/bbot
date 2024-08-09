from ..bbot_fixtures import *  # noqa: F401


@pytest.mark.asyncio
async def test_config(bbot_scanner):
    config = OmegaConf.create(
        {
            "plumbus": "asdf",
            "speculate": True,
            "modules": {
                "ipneighbor": {"test_option": "ipneighbor"},
                "python": {"test_option": "asdf"},
                "speculate": {"test_option": "speculate"},
            },
        }
    )
    scan1 = bbot_scanner("127.0.0.1", modules=["ipneighbor"], config=config)
    await scan1.load_modules()
    assert scan1.config.web.user_agent == "BBOT Test User-Agent"
    assert scan1.config.plumbus == "asdf"
    assert scan1.modules["ipneighbor"].config.test_option == "ipneighbor"
    assert scan1.modules["python"].config.test_option == "asdf"
    assert scan1.modules["speculate"].config.test_option == "speculate"

    await scan1._cleanup()
