import sys
import logging
from pathlib import Path
from omegaconf import OmegaConf

from bbot import cli
from .bbot_fixtures import bbot_config, ensure_root  # noqa: F401

log = logging.getLogger(f"bbot.test")


def test_gowitness(monkeypatch, bbot_config, ensure_root):  # noqa: F811

    config = OmegaConf.merge(bbot_config, OmegaConf.create({"force_deps": True}))

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(cli, "config", config)
    monkeypatch.setattr(
        sys, "argv", ["bbot", "-y", "-m", "gowitness", "httpx", "-t", "http://www.example.com", "-n", "gowitness_test"]
    )
    cli.main()

    screenshots_path = Path(bbot_config["home"]) / "scans" / "gowitness_test" / "gowitness" / "screenshots"
    screenshots = list(screenshots_path.glob("*.png"))
    assert screenshots, "Gowitness failed to generate screenshots"
