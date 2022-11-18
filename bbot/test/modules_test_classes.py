import re
import json

from .helpers import *


class Httpx(HttpxMockHelper):
    def mock_args(self):
        respond_args = {"response_data": json.dumps({"foo": "bar"})}
        self.set_expect_requests(respond_args=respond_args)

    def check_events(self, events):
        for e in events:
            if e.type == "HTTP_RESPONSE" and json.loads(e.data["body"])["foo"] == "bar":
                return True
        return False


class Gowitness(HttpxMockHelper):
    additional_modules = ["httpx"]
    import shutil
    from pathlib import Path

    home_dir = Path("/tmp/.bbot_gowitness_test")
    shutil.rmtree(home_dir, ignore_errors=True)
    config_overrides = {"force_deps": True, "home": str(home_dir)}

    def mock_args(self):
        respond_args = {
            "response_data": "<html><head><title>BBOT is life</title></head><body><big> Contents... </big></body></html>"
        }
        self.set_expect_requests(respond_args=respond_args)

    def check_events(self, events):
        screenshots_path = self.home_dir / "scans" / "gowitness_test" / "gowitness" / "screenshots"
        screenshots = list(screenshots_path.glob("*.png"))
        if screenshots:
            return True
        return False


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


class Anubisdb(RequestMockHelper):
    def setup(self):
        self.module.abort_if = lambda e: False

    def mock_args(self):
        for t in self.targets:
            self.register_uri(
                f"https://jldc.me/anubis/subdomains/{t}",
                json=["asdf.blacklanternsecurity.com", "zzzz.blacklanternsecurity.com"],
            )

    def check_events(self, events):
        for e in events:
            if e == "asdf.blacklanternsecurity.com":
                return True
        return False


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
            if (
                e.type == "VULNERABILITY"
                and e.data["description"]
                == "Known MachineKey found. EncryptionKey: [8CCFBC5B7589DD37DC3B4A885376D7480A69645DAEEC74F418B4877BEC008156], Encryption Algorithm: [AES] ValidationKey: [0F97BAE23F6F36801ABDB5F145124E00A6F795A97093D778EE5CD24F35B78B6FC4C0D0D4420657689C4F321F8596B59E83F02E296E970C4DEAD2DFE226294979] ValidationAlgo:  [SHA1]"
            ):
                return True
        return False


class Telerik(HttpxMockHelper):

    additional_modules = ["httpx"]
    config_overrides = {"modules": {"telerik": {"exploit_RAU_crypto": True}}}

    def mock_args(self):

        # Simulate Telerik.Web.UI.WebResource.axd?type=rau detection
        expect_args = {"method": "GET", "uri": "/Telerik.Web.UI.WebResource.axd", "query_string": "type=rau"}
        respond_args = {
            "response_data": '{ "message" : "RadAsyncUpload handler is registered succesfully, however, it may not be accessed directly." }'
        }
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate Vulnerable Telerik.Web.UI.WebResource.axd
        vuln_data = "ATTu5i4R+ViNFYO6kst0jC11wM/1iqH+W/isjhaDjNuCI7eJ/BY5d1E9eqZK27CJCMuon9u8/hgRIM/cTlgLlv4qOYjPBjs81Y3dAZAdtIr3TXiCmZi9M09a1BYMxjvGKfVky3b7PoOppeWS/3rglTwL1e8oyqLGx2NKUH5y8Cd+kLKV2f31J1sV4I5HTDKgDmvziJp3zlDrCb0Fi9ilKH+O1cbVx6SdBop/U30FxLaB/QIbt2N1rQHREJ5Skpgo7dilPxzBaTObdBhCVyB/FiJhenS/0u3h0Mpi6+A40SylICcyyxQha7+Uh7lEJ8Ne+2eTs4WqcaaQbvIhy7oHc+D0soxRKMZRjo7Up+UWHQJJh6KtWSCxUESNSdNcxjPQZE9HqsPlldVlkeC+ehSGce5bR0Ylots6Iz1OoCgMEWwxByeG3VzgxF6XpitL61A1hFcNo9euSTnCfOWh0vrQHON7DN5LpM9xr7SoD0Dnu01hZ9NS1PHhPLyN5WS87u5qdZp/z3Sxwc3wawIdo62RNf4Iz2gAKJZnPfxrE1mRn5kBe7f6O44rcuv6lcdao/DGlwbERKwRI6/n+FxGmc7H5iEKyihIwS2XUoOgsYTx5CWCDM8CuOXTk+H5fPYp9APRPbkD1IS9I/vRmvNPwWsgv8/7DzttqdBsGxiZJfCw1uZ7KSVmbItgXPAcscNxGEMaHXyJzkAl/mlM5/t/YSejwYoSW6jFfQcLdaVx2dpIpl5UmmQjFedzKeiNqpZDCk4yzXFHX24XUODYMJDtIJK2Hz1KTZmFG+LAOJjB9QOI58hFAnytcKay+JWFrzah/IvoNZxJUtlYdxw0YEyKs/ExET7AXgYQN0S+8j2PfaMMpzDSctTqpp5XBFV4Mt718GiqVnQJtWQv2p9Xl8XXOerBthbzzAciVcB8AV2WfZ51W3e4aX4kcyT/sCJhm7NR5WrNG5mX/ns0TTnGnzlPYhJcbu8uMFjMGDpXuhVyroJ7wmZucaIvesg0h5Y9cMEFviqsdy15vjMzFh+v9uO9Vicf6n9Z9JGSpWKE8wer2JU5b53Zw0cTfulAAffLWXnzOnfu&6R/cGaqQeHVAzdJ9wTFOyCsrMSTtqcjLe8AHwiPckPDUwecnJyNlkDYwDQpxGYQ9hs6YxhupK310sbCbtXB4H6Dz5rGNL40nkkyo4j2clmRr08jtFsPQ0RpE5BGsulPT3l0MxyAvPFMs8bMybUyAP+9RB9LoHE3Xo8BqDadX3HQakpPfGtiDMp+wxkWRgaNpCnXeY1QewWTF6z/duLzbu6CT6s+H4HgBHrOLTpemC2PvP2bDm0ySPHLdpapLYxU8nIYjLKIyYJgwv9S9jNckIVpcGVTWVul7CauCKxAB2mMnM9jJi8zfFwKajT5d2d9XfpkiVMrdlmikSB/ehyX1wQ=="
        expect_args = {
            "method": "POST",
            "uri": "/Telerik.Web.UI.WebResource.axd",
            "query_string": "type=rau",
            "data": vuln_data,
        }
        respond_args = {
            "response_data": '{"fileInfo":{"FileName":"RAU_crypto.bypass","ContentType":"text/html","ContentLength":5,"DateJson":"2019-01-02T03:04:05.067Z","Index":0}, "metaData":"CS8S/Z0J/b2982DRxDin0BBslA7fI0cWMuWlPu4W3FkE4tKaVoIEiAOtVlJ6D+0RQsfu8ox6gvMYxceQ0LtWyTkQBaIUa8LgLQg05DMaQuufHNx0YQ2ACi5neqDBvduj2MGiSGC0hNKzSWsHystZGUfFPLTZuJXYnff+WXurecuRzSI7d4Q1aj0bcTKKvfyQtH+fsTEafWRRZ99X/xgi4ON2OsRZ738uQHw7pQT2e1v7AtN46mxO/BmhEuZQr6m6HEvxK0pJRNkBhFUiQ+poeu8j3JzicOjvPDwFE4Rjqf3RVILt83XZrju2VpRIJqAEtf//znhH8BhT5BWvhnRo+J3ML5qoZLa2joE/QK8Ctf3UPvAFkHIUMdOH2mLNgZ+U87tdVE6fYfzvphZsLxmJRG45H8ZTZuYhJbOfei2LQ4fqHmr7p8KpJNVqoz/ev1dnBclAf5ayb40qJKEVsGXIbWEbIZwg7TTsLFc29aP7DPg=" }'
        }
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate DialogHandler detection
        expect_args = {"method": "GET", "uri": "Telerik.Web.UI.SpellCheckHandler.axd"}
        respond_args = {"status": 500}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate DialogHandler detection
        expect_args = {"method": "GET", "uri": "/App_Master/Telerik.Web.UI.DialogHandler.aspx"}
        respond_args = {
            "response_data": '<input type="hidden" name="dialogParametersHolder" id="dialogParametersHolder" /><div style=\'color:red\'>Cannot deserialize dialog parameters. Please refresh the editor page.</div><div>Error Message:Invalid length for a Base-64 char array or string.</div></form></body></html>'
        }
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Fallback
        expect_args = {"uri": re.compile(r"^/\w{10}$")}
        respond_args = {"status": 200}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):

        telerik_axd_detection = False
        telerik_axd_vulnerable = False
        telerik_spellcheck_detection = False
        telerik_dialoghandler_detection = False

        for e in events:
            print(e)
            if e.type == "FINDING" and "Telerik RAU AXD Handler detected" in e.data["description"]:
                telerik_axd_detection = True
                continue

            if e.type == "VULNERABILITY" and "Confirmed Vulnerable Telerik (version: 2014.3.1024)":
                telerik_axd_vulnerable = True
                continue

            if e.type == "FINDING" and "Telerik DialogHandler detected" in e.data["description"]:
                telerik_dialoghandler_detection = True
                continue

            if e.type == "FINDING" and "Telerik SpellCheckHandler detected" in e.data["description"]:
                telerik_spellcheck_detection = True
                continue

        if (
            telerik_axd_detection
            and telerik_axd_vulnerable
            and telerik_spellcheck_detection
            and telerik_dialoghandler_detection
        ):
            return True
        return False


class Getparam_brute(HttpxMockHelper):

    getparam_body = """
    <html>
    <title>the title</title>
    <body>
    <p>Hello null!</p>';
    </body>
    </html>
    """

    getparam_body_match = """
    <html>
    <title>the title</title>
    <body>
    <p>Hello AAAAAAAAAAAAAA!</p>';
    </body>
    </html>
    """
    additional_modules = ["httpx"]

    config_overrides = {"modules": {"getparam_brute": {"wordlist": tempwordlist(["canary", "id"])}}}

    def setup(self):
        from bbot.core.helpers import helper

        self.module.rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        helper.HttpCompare.gen_cache_buster = lambda *args, **kwargs: {"AAAAAA": "1"}

    def mock_args(self):

        expect_args = {"query_string": b"id=AAAAAAAAAAAAAA&AAAAAA=1"}
        respond_args = {"response_data": self.getparam_body_match}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        respond_args = {"response_data": self.getparam_body}
        self.set_expect_requests(respond_args=respond_args)

    def check_events(self, events):
        for e in events:
            if e.type == "FINDING" and e.data["description"] == "[GETPARAM_BRUTE] Getparam: [id] Reasons: [body]":
                return True
        return False
