import json
import shutil
import logging
from pathlib import Path
from omegaconf import OmegaConf

from ..helpers import *
from ..bbot_fixtures import *  # noqa: F401

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


class Otx(RequestMockHelper):
    def mock_args(self):
        for t in self.targets:
            self.register_uri(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{t}/passive_dns",
                json={
                    "passive_dns": [
                        {
                            "address": "2606:50c0:8000::153",
                            "first": "2021-10-28T20:23:08",
                            "last": "2022-08-24T18:29:49",
                            "hostname": "asdf.blacklanternsecurity.com",
                            "record_type": "AAAA",
                            "indicator_link": "/indicator/hostname/www.blacklanternsecurity.com",
                            "flag_url": "assets/images/flags/us.png",
                            "flag_title": "United States",
                            "asset_type": "hostname",
                            "asn": "AS54113 fastly",
                        }
                    ]
                },
            )

    def check_events(self, events):
        for e in events:
            if e == "asdf.blacklanternsecurity.com":
                return True
        return False


class Httpx(HttpxMockHelper):
    def mock_args(self):
        respond_args = {"response_data": json.dumps({"foo": "bar"})}
        self.set_expect_requests(respond_args=respond_args)

    def check_events(self, events):
        for e in events:
            if e.type == "HTTP_RESPONSE" and json.loads(e.data["body"])["foo"] == "bar":
                return True
        return False


def test_otx(bbot_config, bbot_scanner, bbot_httpserver):
    x = Otx(bbot_config, bbot_scanner)
    x.run()


def test_httpx(bbot_config, bbot_scanner, bbot_httpserver):
    x = Httpx(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()
