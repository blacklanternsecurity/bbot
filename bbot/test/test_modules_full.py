import shutil
import logging
from pathlib import Path
from omegaconf import OmegaConf

from .bbot_fixtures import bbot_config

log = logging.getLogger(f"bbot.test")


def test_module_httpx_gowitness(bbot_config):  # noqa: F811
    """
    Test httpx and gowitness
    """

    from bbot.scanner import Scanner

    home_dir = Path("/tmp/.bbot_gowitness_test")
    shutil.rmtree(home_dir, ignore_errors=True)
    config = OmegaConf.merge(bbot_config, OmegaConf.create({"force_deps": True, "home": str(home_dir)}))

    scan = Scanner("http://www.example.com", modules=["httpx", "gowitness"], name="gowitness_test", config=config)
    events = list(scan.start())
    assert any((e.type == "URL" and e.host == "www.example.com") for e in events)
    assert (home_dir / "tools" / "httpx").is_file(), "Failed to download httpx"
    assert (home_dir / "tools" / "gowitness").is_file(), "Failed to download gowitness"

    screenshots_path = home_dir / "scans" / "gowitness_test" / "gowitness" / "screenshots"
    screenshots = list(screenshots_path.glob("*.png"))
    assert screenshots, "Gowitness failed to generate screenshots"
