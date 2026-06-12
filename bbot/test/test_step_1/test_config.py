from ..bbot_fixtures import *  # noqa: F401


@pytest.mark.asyncio
async def test_config(bbot_scanner):
    # config is strictly validated, so propagation must be tested with real keys
    config = {
        "status_frequency": 5,
        "speculate": True,
        "modules": {
            "ipneighbor": {"num_bits": 8},
            "python": {"module_timeout": 60},
            "speculate": {"module_timeout": 60},
        },
    }
    scan1 = bbot_scanner("127.0.0.1", modules=["ipneighbor"], config=config)
    await scan1._prep()
    assert scan1.config["web"]["user_agent"] == "BBOT Test User-Agent"
    assert scan1.config["status_frequency"] == 5
    assert scan1.modules["ipneighbor"].config["num_bits"] == 8
    assert scan1.modules["python"].config["module_timeout"] == 60
    assert scan1.modules["speculate"].config["module_timeout"] == 60

    await scan1._cleanup()
