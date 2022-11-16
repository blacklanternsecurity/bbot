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


class Aspnet_viewstate(HttpxMockHelper):

    sample_viewstate = """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" >
<head><title>
    Untitled Page
</title></head>
<body>
    <form method="post" action="./query.aspx" id="form1">
<div class="aspNetHidden">
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="rJdyYspajyiWEjvZ/SMXsU/1Q6Dp1XZ/19fZCABpGqWu+s7F1F/JT1s9mP9ED44fMkninhDc8eIq7IzSllZeJ9JVUME41i8ozheGunVSaESf4nBu" />
</div>

<div class="aspNetHidden">

    <input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="EDD8C9AE" />
    <input type="hidden" name="__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="" />
</div>
    <div>
        <span id="dft">test</span>
    </div>
    </form>
</body>
</html>
"""
    additional_modules = ["httpx"]

    def mock_args(self):
        respond_args = {"response_data": self.sample_viewstate}
        self.set_expect_requests(respond_args=respond_args)

    def check_events(self, events):
        for e in events:
            print(e)
            if (
                e.type == "VULNERABILITY"
                and e.data["description"]
                == "Known MachineKey found. EncryptionKey: [8CCFBC5B7589DD37DC3B4A885376D7480A69645DAEEC74F418B4877BEC008156], Encryption Algorithm: [AES] ValidationKey: [0F97BAE23F6F36801ABDB5F145124E00A6F795A97093D778EE5CD24F35B78B6FC4C0D0D4420657689C4F321F8596B59E83F02E296E970C4DEAD2DFE226294979] ValidationAlgo:  [SHA1]"
            ):
                return True
        return False

def test_aspnet_viewstate(bbot_config, bbot_scanner, bbot_httpserver):
    x = Aspnet_viewstate(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()
