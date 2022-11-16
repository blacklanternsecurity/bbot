import shutil
import logging
from omegaconf import OmegaConf

from ..bbot_fixtures import *  # noqa: F401
from ..modules_test_classes import *


log = logging.getLogger(f"bbot.test")


def test_module_httpx_gowitness(bbot_config, bbot_scanner):  # noqa: F811
    """
    Test httpx and gowitness
    """

    home_dir = Path("/tmp/.bbot_gowitness_test")
    shutil.rmtree(home_dir, ignore_errors=True)
    config = OmegaConf.merge(bbot_config, OmegaConf.create({"force_deps": True, "home": str(home_dir)}))

    scan1 = bbot_scanner(
        "http://www.example.com", modules=["httpx", "gowitness"], name="gowitness_test", config=config
    )
    events = list(scan1.start())
    assert any((e.type == "URL" and e.host == "www.example.com") for e in events)
    assert (home_dir / "tools" / "httpx").is_file(), "Failed to download httpx"
    assert (home_dir / "tools" / "gowitness").is_file(), "Failed to download gowitness"

    screenshots_path = home_dir / "scans" / "gowitness_test" / "gowitness" / "screenshots"
    screenshots = list(screenshots_path.glob("*.png"))
    assert screenshots, "Gowitness failed to generate screenshots"


def test_gowitness(bbot_config, bbot_scanner, bbot_httpserver):
    x = Gowitness(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_otx(bbot_config, bbot_scanner, bbot_httpserver):
    x = Otx(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_httpx(bbot_config, bbot_scanner, bbot_httpserver):
    x = Httpx(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_aspnet_viewstate(bbot_config, bbot_scanner, bbot_httpserver):
    x = Aspnet_viewstate(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()
