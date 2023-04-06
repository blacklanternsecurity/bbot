import re
import json
import logging

from .helpers import *

log = logging.getLogger(f"bbot.test")


class Httpx(HttpxMockHelper):
    def mock_args(self):
        request_args = dict(headers={"test": "header"})
        respond_args = dict(response_data=json.dumps({"foo": "bar"}))
        self.set_expect_requests(request_args, respond_args)

    def check_events(self, events):
        for e in events:
            if e.type == "HTTP_RESPONSE":
                j = json.loads(e.data["body"])
                if j.get("foo", "") == "bar":
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
            "response_data": """<html><head><title>BBOT is life</title></head><body>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Open+Sans+Condensed:wght@700&family=Open+Sans:ital,wght@0,400;0,600;0,700;0,800;1,400&display=swap" rel="stylesheet">
</body></html>""",
            "headers": {"Server": "Apache/2.4.41 (Ubuntu)"},
        }
        self.set_expect_requests(respond_args=respond_args)

    def check_events(self, events):
        screenshots_path = self.home_dir / "scans" / "gowitness_test" / "gowitness" / "screenshots"
        screenshots = list(screenshots_path.glob("*.png"))
        assert screenshots, f"No .png files found at {screenshots_path}"
        url = False
        webscreenshot = False
        technology = False
        for event in events:
            if event.type == "URL_UNVERIFIED":
                url = True
            elif event.type == "WEBSCREENSHOT":
                webscreenshot = True
            elif event.type == "TECHNOLOGY":
                technology = True
        assert url, "No URL emitted"
        assert webscreenshot, "No WEBSCREENSHOT emitted"
        assert technology, "No TECHNOLOGY emitted"
        return True


class Excavate(HttpxMockHelper):
    additional_modules = ["httpx"]
    targets = ["http://127.0.0.1:8888/", "test.notreal", "http://127.0.0.1:8888/subdir/links.html"]

    config_overrides = {"web_spider_distance": 1, "web_spider_depth": 1}

    def setup(self):
        self.bbot_httpserver.no_handler_status_code = 404

    def mock_args(self):
        response_data = """
        ftp://ftp.test.notreal
        \\nhttps://www1.test.notreal
        \\x3dhttps://www2.test.notreal
        %0ahttps://www3.test.notreal
        \\u000ahttps://www4.test.notreal
        \nwww5.test.notreal
        \\x3dwww6.test.notreal
        %0awww7.test.notreal
        \\u000awww8.test.notreal
        <a src="http://www9.test.notreal">
        """
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": response_data}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # verify relatives path a-tag parsing is working correctly

        expect_args = {"method": "GET", "uri": "/subdir/links.html"}
        respond_args = {"response_data": "<a href='../relative.html'>relative</a>"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/relative.html"}
        respond_args = {"response_data": "alive"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        event_data = [e.data for e in events]
        assert "https://www1.test.notreal/" in event_data
        assert "https://www2.test.notreal/" in event_data
        assert "https://www3.test.notreal/" in event_data
        assert "https://www4.test.notreal/" in event_data
        assert "www1.test.notreal" in event_data
        assert "www2.test.notreal" in event_data
        assert "www3.test.notreal" in event_data
        assert "www4.test.notreal" in event_data
        assert "www5.test.notreal" in event_data
        assert "www6.test.notreal" in event_data
        assert "www7.test.notreal" in event_data
        assert "www8.test.notreal" in event_data
        assert "http://www9.test.notreal/" in event_data

        assert "nhttps://www1.test.notreal/" not in event_data
        assert "x3dhttps://www2.test.notreal/" not in event_data
        assert "a2https://www3.test.notreal/" not in event_data
        assert "uac20https://www4.test.notreal/" not in event_data
        assert "nwww5.test.notreal" not in event_data
        assert "x3dwww6.test.notreal" not in event_data
        assert "a2www7.test.notreal" not in event_data
        assert "uac20www8.test.notreal" not in event_data

        assert any(
            e.type == "FINDING" and e.data.get("description", "") == "Non-HTTP URI: ftp://ftp.test.notreal"
            for e in events
        )
        assert any(
            e.type == "PROTOCOL"
            and e.data.get("protocol", "") == "FTP"
            and e.data.get("host", "") == "ftp.test.notreal"
            for e in events
        )

        assert any(
            e.type == "URL_UNVERIFIED"
            and e.data == "http://127.0.0.1:8888/relative.html"
            and "spider-danger" not in e.tags
            for e in events
        )
        return True


class Subdomain_Hijack(HttpxMockHelper):
    additional_modules = ["httpx", "excavate"]

    def mock_args(self):
        fingerprints = self.module.fingerprints
        assert fingerprints, "No subdomain hijacking fingerprints available"
        fingerprint = next(iter(fingerprints))
        rand_string = self.scan.helpers.rand_string(length=15, digits=False)
        self.rand_subdomain = f"{rand_string}.{next(iter(fingerprint.domains))}"
        respond_args = {"response_data": f'<a src="http://{self.rand_subdomain}"/>'}
        self.set_expect_requests(respond_args=respond_args)

    def check_events(self, events):
        for event in events:
            if (
                event.type == "FINDING"
                and event.data["description"].startswith("Hijackable Subdomain")
                and self.rand_subdomain in event.data["description"]
                and event.data["host"] == self.rand_subdomain
            ):
                return True
        return False


class Fingerprintx(HttpxMockHelper):
    targets = ["127.0.0.1:8888"]

    def mock_args(self):
        pass

    def check_events(self, events):
        for event in events:
            if (
                event.type == "PROTOCOL"
                and event.host == self.scan.helpers.make_ip_type("127.0.0.1")
                and event.port == 8888
                and event.data["protocol"] == "HTTP"
            ):
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
            if e.data == "asdf.blacklanternsecurity.com":
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
            if e.data == "asdf.blacklanternsecurity.com":
                return True
        return False


class SecretsDB(HttpxMockHelper):
    additional_modules = ["httpx"]

    def mock_args(self):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "-----BEGIN PGP PRIVATE KEY BLOCK-----"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        return any(e.type == "FINDING" for e in events)


class Badsecrets(HttpxMockHelper):
    targets = [
        "http://127.0.0.1:8888/",
        "http://127.0.0.1:8888/test.aspx",
        "http://127.0.0.1:8888/cookie.aspx",
        "http://127.0.0.1:8888/cookie2.aspx",
    ]

    sample_viewstate = """
    <form method="post" action="./query.aspx" id="form1">
<div class="aspNetHidden">
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="rJdyYspajyiWEjvZ/SMXsU/1Q6Dp1XZ/19fZCABpGqWu+s7F1F/JT1s9mP9ED44fMkninhDc8eIq7IzSllZeJ9JVUME41i8ozheGunVSaESf4nBu" />
</div>

<div class="aspNetHidden">

    <input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="EDD8C9AE" />
    <input type="hidden" name="__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="" />
</div>
    </form>
</body>
</html>
"""

    sample_viewstate_notvuln = """
    <form method="post" action="./query.aspx" id="form1">
<div class="aspNetHidden">
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="AAAAYspajyiWEjvZ/SMXsU/1Q6Dp1XZ/19fZCABpGqWu+s7F1F/JT1s9mP9ED44fMkninhDc8eIq7IzSllZeJ9JVUME41i8ozheGunVSaESfAAAA" />
</div>

<div class="aspNetHidden">

    <input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="EDD8C9AE" />
    <input type="hidden" name="__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="" />
</div>
    </form>
</body>
</html>
"""

    additional_modules = ["httpx"]

    def mock_args(self):
        expect_args = {"uri": "/test.aspx"}
        respond_args = {"response_data": self.sample_viewstate}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        respond_args = {"response_data": self.sample_viewstate_notvuln}
        self.set_expect_requests(respond_args=respond_args)

        expect_args = {"uri": "/cookie.aspx"}
        respond_args = {
            "response_data": "<html><body><p>JWT Cookie Test</p></body></html>",
            "headers": {
                "set-cookie": "vulnjwt=eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo; secure"
            },
        }
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"uri": "/cookie2.aspx"}
        respond_args = {
            "response_data": "<html><body><p>Express Cookie Test</p></body></html>",
            "headers": {
                "set-cookie": "connect.sid=s%3A8FnPwdeM9kdGTZlWvdaVtQ0S1BCOhY5G.qys7H2oGSLLdRsEq7sqh7btOohHsaRKqyjV4LiVnBvc; Path=/; Expires=Wed, 05 Apr 2023 04:47:29 GMT; HttpOnly"
            },
        }
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        SecretFound = False
        IdentifyOnly = False
        CookieBasedDetection = False
        CookieBasedDetection_2 = False

        for e in events:
            if (
                e.type == "VULNERABILITY"
                and e.data["description"]
                == "Known Secret Found. Secret Type: [ASP.NET MachineKey] Secret: [validationKey: 0F97BAE23F6F36801ABDB5F145124E00A6F795A97093D778EE5CD24F35B78B6FC4C0D0D4420657689C4F321F8596B59E83F02E296E970C4DEAD2DFE226294979 validationAlgo: SHA1 encryptionKey: 8CCFBC5B7589DD37DC3B4A885376D7480A69645DAEEC74F418B4877BEC008156 encryptionAlgo: AES] Product Type: [ASP.NET Viewstate] Product: [rJdyYspajyiWEjvZ/SMXsU/1Q6Dp1XZ/19fZCABpGqWu+s7F1F/JT1s9mP9ED44fMkninhDc8eIq7IzSllZeJ9JVUME41i8ozheGunVSaESf4nBu] Detecting Module: [ASPNET_Viewstate]"
            ):
                SecretFound = True

            if (
                e.type == "FINDING"
                and e.data["description"]
                == "Cryptographic Product identified. Product Type: [ASP.NET Viewstate] Product: [AAAAYspajyiWEjvZ/SMXsU/1Q6Dp1XZ/19fZCABpGqWu+s7F1F/JT1s9mP9ED44fMkninhDc8eIq7IzSllZeJ9JVUME41i8ozheGunVSaESfAAAA] Detecting Module: [ASPNET_Viewstate]"
            ):
                IdentifyOnly = True

            if (
                e.type == "VULNERABILITY"
                and e.data["description"]
                == "Known Secret Found. Secret Type: [HMAC/RSA Key] Secret: [1234] Product Type: [JSON Web Token (JWT)] Product: [eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo] Detecting Module: [Generic_JWT]"
            ):
                CookieBasedDetection = True

            if (
                e.type == "VULNERABILITY"
                and e.data["description"]
                == "Known Secret Found. Secret Type: [Express SESSION_SECRET] Secret: [keyboard cat] Product Type: [Express Signed Cookie] Product: [s%3A8FnPwdeM9kdGTZlWvdaVtQ0S1BCOhY5G.qys7H2oGSLLdRsEq7sqh7btOohHsaRKqyjV4LiVnBvc] Detecting Module: [ExpressSignedCookies]"
            ):
                print(e.data["description"])
                CookieBasedDetection_2 = True

        if SecretFound and IdentifyOnly and CookieBasedDetection and CookieBasedDetection_2:
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


class Paramminer_getparams(HttpxMockHelper):
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

    config_overrides = {"modules": {"paramminer_getparams": {"wordlist": tempwordlist(["canary", "id"])}}}

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
            if e.type == "FINDING" and e.data["description"] == "[Paramminer] Getparam: [id] Reasons: [body]":
                return True
        return False


class Paramminer_headers(HttpxMockHelper):
    headers_body = """
    <html>
    <title>the title</title>
    <body>
    <p>Hello null!</p>';
    </body>
    </html>
    """

    headers_body_match = """
    <html>
    <title>the title</title>
    <body>
    <p>Hello AAAAAAAAAAAAAA!</p>';
    </body>
    </html>
    """
    additional_modules = ["httpx"]

    config_overrides = {"modules": {"paramminer_headers": {"wordlist": tempwordlist(["junkword1", "tracestate"])}}}

    def setup(self):
        from bbot.core.helpers import helper

        self.module.rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        helper.HttpCompare.gen_cache_buster = lambda *args, **kwargs: {"AAAAAA": "1"}

    def mock_args(self):
        expect_args = dict(headers={"tracestate": "AAAAAAAAAAAAAA"})
        respond_args = {"response_data": self.headers_body_match}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        respond_args = {"response_data": self.headers_body}
        self.set_expect_requests(respond_args=respond_args)

    def check_events(self, events):
        for e in events:
            if e.type == "FINDING" and e.data["description"] == "[Paramminer] Header: [tracestate] Reasons: [body]":
                return True
        return False


class Paramminer_cookies(HttpxMockHelper):
    cookies_body = """
    <html>
    <title>the title</title>
    <body>
    <p>Hello null!</p>';
    </body>
    </html>
    """

    cookies_body_match = """
    <html>
    <title>the title</title>
    <body>
    <p>Hello AAAAAAAAAAAAAA!</p>';
    </body>
    </html>
    """
    additional_modules = ["httpx"]

    config_overrides = {"modules": {"paramminer_cookies": {"wordlist": tempwordlist(["junkcookie", "admincookie"])}}}

    def setup(self):
        from bbot.core.helpers import helper

        self.module.rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        helper.HttpCompare.gen_cache_buster = lambda *args, **kwargs: {"AAAAAA": "1"}

    def mock_args(self):
        expect_args = dict(headers={"Cookie": "admincookie=AAAAAAAAAAAAAA"})
        respond_args = {"response_data": self.cookies_body_match}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        respond_args = {"response_data": self.cookies_body}
        self.set_expect_requests(respond_args=respond_args)

    def check_events(self, events):
        for e in events:
            if e.type == "FINDING" and e.data["description"] == "[Paramminer] Cookie: [admincookie] Reasons: [body]":
                return True
        return False


class LeakIX(RequestMockHelper):
    def mock_args(self):
        self.register_uri(
            "https://leakix.net/api/subdomains/blacklanternsecurity.com",
            json=[
                {
                    "subdomain": "www.blacklanternsecurity.com",
                    "distinct_ips": 2,
                    "last_seen": "2023-02-20T20:23:13.583Z",
                },
                {
                    "subdomain": "asdf.blacklanternsecurity.com",
                    "distinct_ips": 1,
                    "last_seen": "2022-09-17T01:31:52.563Z",
                },
            ],
        )

    def check_events(self, events):
        www = False
        asdf = False
        for e in events:
            if e.type in ("DNS_NAME", "DNS_NAME_UNRESOLVED"):
                if e.data == "www.blacklanternsecurity.com":
                    www = True
                elif e.data == "asdf.blacklanternsecurity.com":
                    asdf = True
        return www and asdf


class Massdns(MockHelper):
    subdomain_wordlist = tempwordlist(["www", "asdf"])
    config_overrides = {"modules": {"massdns": {"wordlist": str(subdomain_wordlist)}}}

    def __init__(self, *args, **kwargs):
        with requests_mock.Mocker() as m:
            m.register_uri(
                "GET",
                "https://raw.githubusercontent.com/blacklanternsecurity/public-dns-servers/master/nameservers.txt",
                text="8.8.8.8\n8.8.4.4\n1.1.1.1",
            )
            super().__init__(*args, **kwargs)

    def check_events(self, events):
        for e in events:
            if e.type in ("DNS_NAME", "DNS_NAME_UNRESOLVED") and e.data == "www.blacklanternsecurity.com":
                return True
        return False


class Robots(HttpxMockHelper):
    additional_modules = ["httpx"]

    config_overrides = {"modules": {"robots": {"include_sitemap": True}}}

    def mock_args(self):
        sample_robots = f"Allow: /allow/\nDisallow: /disallow/\nJunk: test.com\nDisallow: /*/wildcard.txt\nSitemap: {self.targets[0]}sitemap.txt"

        expect_args = {"method": "GET", "uri": "/robots.txt"}
        respond_args = {"response_data": sample_robots}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        allow_bool = False
        disallow_bool = False
        sitemap_bool = False
        wildcard_bool = False

        for e in events:
            if e.type == "URL_UNVERIFIED":
                if e.data == "http://127.0.0.1:8888/allow/":
                    allow_bool = True

                if e.data == "http://127.0.0.1:8888/disallow/":
                    disallow_bool = True

                if e.data == "http://127.0.0.1:8888/sitemap.txt":
                    sitemap_bool = True

                if re.match(r"http://127\.0\.0\.1:8888/\w+/wildcard\.txt", e.data):
                    wildcard_bool = True

        if allow_bool and disallow_bool and sitemap_bool and wildcard_bool:
            return True
        return False


class Masscan(MockHelper):
    targets = ["8.8.8.8/32"]
    config_overrides = {"modules": {"masscan": {"ports": "443", "wait": 1}}}
    config_overrides_2 = {"modules": {"masscan": {"ports": "443", "wait": 1, "use_cache": True}}}
    masscan_output = """[
{   "ip": "8.8.8.8",   "timestamp": "1680197558", "ports": [ {"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 54} ] }
]"""
    masscan_config = """seed = 17230484647655100360
rate = 600       
shard = 1/1


# TARGET SELECTION (IP, PORTS, EXCLUDES)
ports = 
range = 9.8.7.6"""

    def __init__(self, config, bbot_scanner, *args, **kwargs):
        super().__init__(config, bbot_scanner, *args, **kwargs)
        self.scan.modules["masscan"].masscan_config = self.masscan_config

        def setup_scan_2():
            config2 = OmegaConf.merge(config, OmegaConf.create(self.config_overrides_2))
            self.scan2 = bbot_scanner(
                *self.targets,
                modules=[self.name] + self.additional_modules,
                name=f"{self.name}_test",
                config=config2,
                whitelist=self.whitelist,
                blacklist=self.blacklist,
            )
            self.patch_scan(self.scan2)
            self.scan2.prep()
            self.scan2.modules["masscan"].masscan_config = self.masscan_config

        self.setup_scan_2 = setup_scan_2
        self.masscan_run = False

    def run_masscan(self, command, *args, **kwargs):
        if "masscan" in command[0]:
            json_output_file = command[-1]
            with open(json_output_file, "w") as f:
                f.write(self.masscan_output)
            self.masscan_run = True
        else:
            return self.scan.helpers.run(command, *args, **kwargs)

    def patch_scan(self, scan):
        scan.helpers.run = self.run_masscan

    def run(self):
        super().run()
        self.setup_scan_2()
        assert self.masscan_run == True, "masscan didn't run when it was supposed to"
        self.masscan_run = False
        events = list(self.scan2.start())
        self.check_events(events)
        assert self.masscan_run == False, "masscan ran when it wasn't supposed to"

    def check_events(self, events):
        assert any(e.type == "IP_ADDRESS" and e.data == "8.8.8.8" for e in events), "No IP_ADDRESS emitted"
        assert any(e.type == "OPEN_TCP_PORT" and e.data == "8.8.8.8:443" for e in events), "No OPEN_TCP_PORT emitted"
        return True


class Buckets(HttpxMockHelper, RequestMockHelper):
    providers = ["aws", "gcp", "azure", "digitalocean", "firebase"]
    # providers = ["aws"]
    additional_modules = ["excavate", "speculate", "httpx"] + [f"bucket_{p}" for p in providers]
    config_overrides = {
        "modules": {
            "bucket_aws": {"permutations": True},
            "bucket_gcp": {"permutations": True},
            "bucket_azure": {"permutations": True},
            "bucket_digitalocean": {"permutations": True},
            "bucket_firebase": {"permutations": True},
        },
        "excavate": True,
        "speculate": True,
    }

    from bbot.core.helpers.misc import rand_string

    random_bucket_name_1 = rand_string(15, digits=False)
    random_bucket_name_2 = rand_string(15, digits=False)

    open_aws_bucket = """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>vpn-static</Name><Prefix></Prefix><Marker></Marker><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>style.css</Key><LastModified>2017-03-18T06:41:59.000Z</LastModified><ETag>&quot;bf9e72bdab09b785f05ff0395023cc35&quot;</ETag><Size>429</Size><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>"""
    open_digitalocean_bucket = """<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>cloud01</Name><Prefix></Prefix><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>test.doc</Key><LastModified>2020-10-14T15:23:37.545Z</LastModified><ETag>&quot;4d25c8699f7347acc9f41e57148c62c0&quot;</ETag><Size>13362425</Size><StorageClass>STANDARD</StorageClass><Owner><ID>1957883</ID><DisplayName>1957883</DisplayName></Owner><Type>Normal</Type></Contents><Marker></Marker></ListBucketResult>"""
    open_gcp_bucket = """{
  "kind": "storage#testIamPermissionsResponse",
  "permissions": [
    "storage.objects.create",
    "storage.objects.list"
  ]
}"""

    def patch_scan(self, scan):
        scan.helpers.word_cloud.mutations = lambda b, cloud=False: [
            (b, "dev"),
        ]

    def mock_args(self):
        expect_args = {"method": "GET", "uri": "/"}
        body = f"""
        <a href="https://{self.random_bucket_name_1}.s3.amazonaws.com"/>
        <a href="https://{self.random_bucket_name_1}.nyc3.digitaloceanspaces.com"/>
        <a href="https://{self.random_bucket_name_1}.storage.googleapis.com"/>
        <a href="https://{self.random_bucket_name_1}.blob.core.windows.net"/>
        <a href="https://{self.random_bucket_name_1}.firebaseio.com"/>

        <a href="https://{self.random_bucket_name_2}.s3-ap-southeast-2.amazonaws.com"/>
        <a href="https://{self.random_bucket_name_2}.fra1.digitaloceanspaces.com"/>
        <a href="https://{self.random_bucket_name_2}.storage.googleapis.com"/>
        <a href="https://{self.random_bucket_name_2}.blob.core.windows.net"/>
        <a href="https://{self.random_bucket_name_2}.firebaseio.com"/>
        """
        self.set_expect_requests(expect_args=expect_args, respond_args={"response_data": body})

    def mock_args_requests(self):
        self.m.register_uri("GET", requests_mock.ANY, text="", status_code=404)
        self.register_uri(
            f"https://{self.random_bucket_name_2}.s3-ap-southeast-2.amazonaws.com/",
            text=self.open_aws_bucket,
        )
        self.register_uri(
            f"https://{self.random_bucket_name_2}.fra1.digitaloceanspaces.com/",
            text=self.open_digitalocean_bucket,
        )
        self.register_uri(
            f"https://{self.random_bucket_name_2}.blob.core.windows.net/{self.random_bucket_name_2}?restype=container",
            text="",
        )
        self.register_uri(
            f"https://www.googleapis.com/storage/v1/b/{self.random_bucket_name_2}/iam/testPermissions?permissions=storage.buckets.setIamPolicy&permissions=storage.objects.list&permissions=storage.objects.get&permissions=storage.objects.create",
            text=self.open_gcp_bucket,
        )
        self.register_uri(
            f"https://{self.random_bucket_name_2}.firebaseio.com/.json",
            text="",
        )

        self.register_uri(
            f"https://{self.random_bucket_name_2}-dev.s3.amazonaws.com/",
            text="",
        )
        self.register_uri(
            f"https://{self.random_bucket_name_2}-dev.fra1.digitaloceanspaces.com/",
            text="",
        )
        self.register_uri(
            f"https://{self.random_bucket_name_2}-dev.blob.core.windows.net/{self.random_bucket_name_2}-dev?restype=container",
            text="",
        )
        self.register_uri(
            f"https://www.googleapis.com/storage/v1/b/{self.random_bucket_name_2}-dev",
            text="",
        )
        self.register_uri(
            f"https://{self.random_bucket_name_2}-dev.firebaseio.com/.json",
            text="",
        )

    def run(self):
        with requests_mock.Mocker() as m:
            self.m = m
            self.mock_args_requests()
            events = list(self.scan.start())
            for e in events:
                print(e)
            self.check_events(events)

    def check_events(self, events):
        for provider in self.providers:
            # make sure buckets were excavated
            assert any(
                e.type == "STORAGE_BUCKET" and str(e.module) == f"{provider}_cloud" for e in events
            ), f'bucket not found for provider "{provider}"'
            # make sure open buckets were found
            if not provider == "azure":
                assert any(
                    e.type == "FINDING" and str(e.module) == f"bucket_{provider}" for e in events
                ), f'open bucket not found for provider "{provider}"'
                for e in events:
                    if e.type == "FINDING" and str(e.module) == f"bucket_{provider}":
                        url = e.data.get("url", "")
                        assert self.random_bucket_name_2 in url
                        assert not self.random_bucket_name_1 in url
            # make sure bucket mutations were found
            assert any(
                e.type == "STORAGE_BUCKET"
                and str(e.module) == f"bucket_{provider}"
                and f"{self.random_bucket_name_2}-dev" in e.data["url"]
                for e in events
            ), f'bucket (dev mutation) not found for provider "{provider}"'


class ASN(RequestMockHelper):
    targets = ["8.8.8.8"]
    response_get_asn_ripe = {
        "messages": [],
        "see_also": [],
        "version": "1.1",
        "data_call_name": "network-info",
        "data_call_status": "supported",
        "cached": False,
        "data": {"asns": ["15169"], "prefix": "8.8.8.0/24"},
        "query_id": "20230217212133-f278ff23-d940-4634-8115-a64dee06997b",
        "process_time": 5,
        "server_id": "app139",
        "build_version": "live.2023.2.1.142",
        "status": "ok",
        "status_code": 200,
        "time": "2023-02-17T21:21:33.428469",
    }
    response_get_asn_metadata_ripe = {
        "messages": [],
        "see_also": [],
        "version": "4.1",
        "data_call_name": "whois",
        "data_call_status": "supported - connecting to ursa",
        "cached": False,
        "data": {
            "records": [
                [
                    {"key": "ASNumber", "value": "15169", "details_link": None},
                    {"key": "ASName", "value": "GOOGLE", "details_link": None},
                    {"key": "ASHandle", "value": "15169", "details_link": "https://stat.ripe.net/AS15169"},
                    {"key": "RegDate", "value": "2000-03-30", "details_link": None},
                    {
                        "key": "Ref",
                        "value": "https://rdap.arin.net/registry/autnum/15169",
                        "details_link": "https://rdap.arin.net/registry/autnum/15169",
                    },
                    {"key": "source", "value": "ARIN", "details_link": None},
                ],
                [
                    {"key": "OrgAbuseHandle", "value": "ABUSE5250-ARIN", "details_link": None},
                    {"key": "OrgAbuseName", "value": "Abuse", "details_link": None},
                    {"key": "OrgAbusePhone", "value": "+1-650-253-0000", "details_link": None},
                    {
                        "key": "OrgAbuseEmail",
                        "value": "network-abuse@google.com",
                        "details_link": "mailto:network-abuse@google.com",
                    },
                    {
                        "key": "OrgAbuseRef",
                        "value": "https://rdap.arin.net/registry/entity/ABUSE5250-ARIN",
                        "details_link": "https://rdap.arin.net/registry/entity/ABUSE5250-ARIN",
                    },
                    {"key": "source", "value": "ARIN", "details_link": None},
                ],
                [
                    {"key": "OrgName", "value": "Google LLC", "details_link": None},
                    {"key": "OrgId", "value": "GOGL", "details_link": None},
                    {"key": "Address", "value": "1600 Amphitheatre Parkway", "details_link": None},
                    {"key": "City", "value": "Mountain View", "details_link": None},
                    {"key": "StateProv", "value": "CA", "details_link": None},
                    {"key": "PostalCode", "value": "94043", "details_link": None},
                    {"key": "Country", "value": "US", "details_link": None},
                    {"key": "RegDate", "value": "2000-03-30", "details_link": None},
                    {
                        "key": "Comment",
                        "value": "Please note that the recommended way to file abuse complaints are located in the following links.",
                        "details_link": None,
                    },
                    {
                        "key": "Comment",
                        "value": "To report abuse and illegal activity: https://www.google.com/contact/",
                        "details_link": None,
                    },
                    {
                        "key": "Comment",
                        "value": "For legal requests: http://support.google.com/legal",
                        "details_link": None,
                    },
                    {"key": "Comment", "value": "Regards,", "details_link": None},
                    {"key": "Comment", "value": "The Google Team", "details_link": None},
                    {
                        "key": "Ref",
                        "value": "https://rdap.arin.net/registry/entity/GOGL",
                        "details_link": "https://rdap.arin.net/registry/entity/GOGL",
                    },
                    {"key": "source", "value": "ARIN", "details_link": None},
                ],
                [
                    {"key": "OrgTechHandle", "value": "ZG39-ARIN", "details_link": None},
                    {"key": "OrgTechName", "value": "Google LLC", "details_link": None},
                    {"key": "OrgTechPhone", "value": "+1-650-253-0000", "details_link": None},
                    {
                        "key": "OrgTechEmail",
                        "value": "arin-contact@google.com",
                        "details_link": "mailto:arin-contact@google.com",
                    },
                    {
                        "key": "OrgTechRef",
                        "value": "https://rdap.arin.net/registry/entity/ZG39-ARIN",
                        "details_link": "https://rdap.arin.net/registry/entity/ZG39-ARIN",
                    },
                    {"key": "source", "value": "ARIN", "details_link": None},
                ],
                [
                    {"key": "RTechHandle", "value": "ZG39-ARIN", "details_link": None},
                    {"key": "RTechName", "value": "Google LLC", "details_link": None},
                    {"key": "RTechPhone", "value": "+1-650-253-0000", "details_link": None},
                    {"key": "RTechEmail", "value": "arin-contact@google.com", "details_link": None},
                    {
                        "key": "RTechRef",
                        "value": "https://rdap.arin.net/registry/entity/ZG39-ARIN",
                        "details_link": None,
                    },
                    {"key": "source", "value": "ARIN", "details_link": None},
                ],
            ],
            "irr_records": [],
            "authorities": ["arin"],
            "resource": "15169",
            "query_time": "2023-02-17T21:25:00",
        },
        "query_id": "20230217212529-75f57efd-59f4-473f-8bdd-803062e94290",
        "process_time": 268,
        "server_id": "app143",
        "build_version": "live.2023.2.1.142",
        "status": "ok",
        "status_code": 200,
        "time": "2023-02-17T21:25:29.417812",
    }
    response_get_asn_bgpview = {
        "status": "ok",
        "status_message": "Query was successful",
        "data": {
            "ip": "8.8.8.8",
            "ptr_record": "dns.google",
            "prefixes": [
                {
                    "prefix": "8.8.8.0/24",
                    "ip": "8.8.8.0",
                    "cidr": 24,
                    "asn": {"asn": 15169, "name": "GOOGLE", "description": "Google LLC", "country_code": "US"},
                    "name": "LVLT-GOGL-8-8-8",
                    "description": "Google LLC",
                    "country_code": "US",
                }
            ],
            "rir_allocation": {
                "rir_name": "ARIN",
                "country_code": None,
                "ip": "8.0.0.0",
                "cidr": 9,
                "prefix": "8.0.0.0/9",
                "date_allocated": "1992-12-01 00:00:00",
                "allocation_status": "allocated",
            },
            "iana_assignment": {
                "assignment_status": "legacy",
                "description": "Administered by ARIN",
                "whois_server": "whois.arin.net",
                "date_assigned": None,
            },
            "maxmind": {"country_code": None, "city": None},
        },
        "@meta": {"time_zone": "UTC", "api_version": 1, "execution_time": "567.18 ms"},
    }
    response_get_emails_bgpview = {
        "status": "ok",
        "status_message": "Query was successful",
        "data": {
            "asn": 15169,
            "name": "GOOGLE",
            "description_short": "Google LLC",
            "description_full": ["Google LLC"],
            "country_code": "US",
            "website": "https://about.google/intl/en/",
            "email_contacts": ["network-abuse@google.com", "arin-contact@google.com"],
            "abuse_contacts": ["network-abuse@google.com"],
            "looking_glass": None,
            "traffic_estimation": None,
            "traffic_ratio": "Mostly Outbound",
            "owner_address": ["1600 Amphitheatre Parkway", "Mountain View", "CA", "94043", "US"],
            "rir_allocation": {
                "rir_name": "ARIN",
                "country_code": "US",
                "date_allocated": "2000-03-30 00:00:00",
                "allocation_status": "assigned",
            },
            "iana_assignment": {
                "assignment_status": None,
                "description": None,
                "whois_server": None,
                "date_assigned": None,
            },
            "date_updated": "2023-02-07 06:39:11",
        },
        "@meta": {"time_zone": "UTC", "api_version": 1, "execution_time": "56.55 ms"},
    }
    config_overrides = {"scope_report_distance": 2}

    def __init__(self, config, bbot_scanner, *args):
        super().__init__(config, bbot_scanner, *args)
        self.scan2 = bbot_scanner(
            *self.targets,
            modules=[self.name] + self.additional_modules,
            name=f"{self.name}_test_2",
            config=self.config,
        )
        self.scan2.prep()
        self.module2 = self.scan2.modules[self.name]

    def mock_args(self):
        pass

    def run(self):
        with requests_mock.Mocker() as m:
            self.m = m
            self.register_uri(
                "https://stat.ripe.net/data/network-info/data.json?resource=8.8.8.8",
                text=json.dumps(self.response_get_asn_ripe),
            )
            self.register_uri(
                "https://stat.ripe.net/data/whois/data.json?resource=15169",
                text=json.dumps(self.response_get_asn_metadata_ripe),
            )
            self.register_uri("https://api.bgpview.io/ip/8.8.8.8", text=json.dumps(self.response_get_asn_bgpview))
            self.register_uri("https://api.bgpview.io/asn/15169", text=json.dumps(self.response_get_emails_bgpview))
            self.module.sources = ["bgpview", "ripe"]
            events = list(e for e in self.scan.start() if e.module == self.module)
            assert self.check_events(events)
            self.module2.sources = ["ripe", "bgpview"]
            events2 = list(e for e in self.scan2.start() if e.module == self.module2)
            assert self.check_events(events2)

    def check_events(self, events):
        asn = False
        email = False
        for e in events:
            if e.type == "ASN":
                asn = True
            elif e.type == "EMAIL_ADDRESS":
                email = True
        return asn and email


class Wafw00f(HttpxMockHelper):
    additional_modules = ["httpx"]

    def mock_args(self):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "Proudly powered by litespeed web server"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        for e in events:
            if e.type == "WAF":
                if "LiteSpeed" in e.data["WAF"]:
                    return True
        return False


class Ffuf(HttpxMockHelper):
    test_wordlist = ["11111111", "admin", "junkword1", "zzzjunkword2"]
    config_overrides = {
        "modules": {
            "ffuf": {
                "wordlist": tempwordlist(test_wordlist),
            }
        }
    }

    additional_modules = ["httpx"]

    def mock_args(self):
        expect_args = {"method": "GET", "uri": "/admin"}
        respond_args = {"response_data": "alive admin page"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        for e in events:
            if e.type == "URL_UNVERIFIED":
                if "admin" in e.data:
                    return True
        return False


class Ffuf_extensions(HttpxMockHelper):
    test_wordlist = ["11111111", "console", "junkword1", "zzzjunkword2"]
    config_overrides = {"modules": {"ffuf": {"wordlist": tempwordlist(test_wordlist), "extensions": "php"}}}

    additional_modules = ["httpx"]

    def mock_args(self):
        expect_args = {"method": "GET", "uri": "/console.php"}
        respond_args = {"response_data": "alive admin page"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        for e in events:
            if e.type == "URL_UNVERIFIED":
                if "console" in e.data:
                    return True
        return False


class Vhost(HttpxMockHelper):
    targets = ["http://localhost:8888", "secret.localhost"]

    additional_modules = ["httpx"]

    test_wordlist = ["11111111", "admin", "cloud", "junkword1", "zzzjunkword2"]
    config_overrides = {
        "modules": {
            "vhost": {
                "wordlist": tempwordlist(test_wordlist),
            }
        }
    }

    def mock_args(self):
        expect_args = {"method": "GET", "uri": "/", "headers": {"Host": "admin.localhost:8888"}}
        respond_args = {"response_data": "Alive vhost admin"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/", "headers": {"Host": "cloud.localhost:8888"}}
        respond_args = {"response_data": "Alive vhost cloud"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/", "headers": {"Host": "q-cloud.localhost:8888"}}
        respond_args = {"response_data": "Alive vhost q-cloud"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/", "headers": {"Host": "secret.localhost:8888"}}
        respond_args = {"response_data": "Alive vhost secret"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/", "headers": {"Host": "host.docker.internal"}}
        respond_args = {"response_data": "Alive vhost host.docker.internal"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        basic_detection = False
        mutaton_of_detected = False
        basehost_mutation = False
        special_vhost_list = False
        wordcloud_detection = False

        for e in events:
            print(e)
            if e.type == "VHOST":
                if e.data["vhost"] == "admin":
                    basic_detection = True
                if e.data["vhost"] == "cloud":
                    mutaton_of_detected = True
                if e.data["vhost"] == "q-cloud":
                    basehost_mutation = True
                if e.data["vhost"] == "host.docker.internal":
                    special_vhost_list = True
                if e.data["vhost"] == "secret":
                    wordcloud_detection = True

        if (
            basic_detection
            and mutaton_of_detected
            and basehost_mutation
            and special_vhost_list
            and wordcloud_detection
        ):
            return True
        return False


class Ffuf_shortnames(HttpxMockHelper):
    test_wordlist = ["11111111", "administrator", "portal", "console", "junkword1", "zzzjunkword2", "directory"]
    config_overrides = {
        "modules": {
            "ffuf_shortnames": {
                "find_common_prefixes": True,
                "find_common_prefixes": True,
                "wordlist": tempwordlist(test_wordlist),
            }
        }
    }

    def setup(self):
        self.bbot_httpserver.no_handler_status_code = 404

        seed_events = []
        parent_event = self.scan.make_event(
            "http://127.0.0.1:8888/", "URL", self.scan.root_event, module="httpx", tags=["status-200", "distance-0"]
        )
        seed_events.append(
            self.scan.make_event(
                "http://127.0.0.1:8888/ADMINI~1.ASP",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-file"],
            )
        )
        seed_events.append(
            self.scan.make_event(
                "http://127.0.0.1:8888/ADM_PO~1.ASP",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-file"],
            )
        )
        seed_events.append(
            self.scan.make_event(
                "http://127.0.0.1:8888/ABCZZZ~1.ASP",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-file"],
            )
        )
        seed_events.append(
            self.scan.make_event(
                "http://127.0.0.1:8888/ABCXXX~1.ASP",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-file"],
            )
        )
        seed_events.append(
            self.scan.make_event(
                "http://127.0.0.1:8888/ABCYYY~1.ASP",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-file"],
            )
        )
        seed_events.append(
            self.scan.make_event(
                "http://127.0.0.1:8888/ABCCON~1.ASP",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-file"],
            )
        )
        seed_events.append(
            self.scan.make_event(
                "http://127.0.0.1:8888/DIRECT~1",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-directory"],
            )
        )
        seed_events.append(
            self.scan.make_event(
                "http://127.0.0.1:8888/ADM_DI~1",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-directory"],
            )
        )
        seed_events.append(
            self.scan.make_event(
                "http://127.0.0.1:8888/XYZDIR~1",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-directory"],
            )
        )
        seed_events.append(
            self.scan.make_event(
                "http://127.0.0.1:8888/XYZAAA~1",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-directory"],
            )
        )
        seed_events.append(
            self.scan.make_event(
                "http://127.0.0.1:8888/XYZBBB~1",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-directory"],
            )
        )
        seed_events.append(
            self.scan.make_event(
                "http://127.0.0.1:8888/XYZCCC~1",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-directory"],
            )
        )
        self.scan.target._events["http://127.0.0.1:8888"] = seed_events

    def mock_args(self):
        expect_args = {"method": "GET", "uri": "/administrator.aspx"}
        respond_args = {"response_data": "alive"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/adm_portal.aspx"}
        respond_args = {"response_data": "alive"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/abcconsole.aspx"}
        respond_args = {"response_data": "alive"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/directory/"}
        respond_args = {"response_data": "alive"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/adm_directory/"}
        respond_args = {"response_data": "alive"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/xyzdirectory/"}
        respond_args = {"response_data": "alive"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        basic_detection = False
        directory_detection = False
        prefix_detection = False
        delimeter_detection = False
        directory_delimeter_detection = False
        prefix_delimeter_detection = False

        for e in events:
            if e.type == "URL_UNVERIFIED":
                if e.data == "http://127.0.0.1:8888/administrator.aspx":
                    basic_detection = True
                if e.data == "http://127.0.0.1:8888/directory/":
                    directory_detection = True
                if e.data == "http://127.0.0.1:8888/adm_portal.aspx":
                    prefix_detection = True
                if e.data == "http://127.0.0.1:8888/abcconsole.aspx":
                    delimeter_detection = True
                if e.data == "http://127.0.0.1:8888/abcconsole.aspx":
                    directory_delimeter_detection = True
                if e.data == "http://127.0.0.1:8888/xyzdirectory/":
                    prefix_delimeter_detection = True

        if (
            basic_detection
            and directory_detection
            and prefix_detection
            and delimeter_detection
            and directory_delimeter_detection
            and prefix_delimeter_detection
        ):
            return True
        return False


class Iis_shortnames(HttpxMockHelper):
    additional_modules = ["httpx"]

    config_overrides = {"modules": {"iis_shortnames": {"detect_only": False}}}

    def setup(self):
        self.bbot_httpserver.no_handler_status_code = 404

    def mock_args(self):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive", "status": 200}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/*~1*/a.aspx"}
        respond_args = {"response_data": "", "status": 400}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": re.compile(r"\/B\*~1\*.*$")}
        respond_args = {"response_data": "", "status": 400}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": re.compile(r"\/BL\*~1\*.*$")}
        respond_args = {"response_data": "", "status": 400}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": re.compile(r"\/BLS\*~1\*.*$")}
        respond_args = {"response_data": "", "status": 400}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": re.compile(r"\/BLSH\*~1\*.*$")}
        respond_args = {"response_data": "", "status": 400}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": re.compile(r"\/BLSHA\*~1\*.*$")}
        respond_args = {"response_data": "", "status": 400}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": re.compile(r"\/BLSHAX\*~1\*.*$")}
        respond_args = {"response_data": "", "status": 400}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        vulnerabilityEmitted = False
        url_hintEmitted = False
        for e in events:
            if e.type == "VULNERABILITY":
                vulnerabilityEmitted = True
            if e.type == "URL_HINT" and e.data == "http://127.0.0.1:8888/BLSHAX~1":
                url_hintEmitted = True

        if vulnerabilityEmitted and url_hintEmitted:
            return True
        return False


class Nuclei_manual(HttpxMockHelper):
    additional_modules = ["httpx", "excavate"]

    test_html = """
    html>
 <head>
  <title>Index of /test</title>
 </head>
 <body>
<h1>Index of /test</h1>
  <table>
   <tr><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th></tr>
   <tr><th colspan="3"><hr></th></tr>
<tr><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td></tr>
</table>
<address>Apache/2.4.38 (Debian) Server at http://127.0.0.1:8888/testmultipleruns.html</address>
</body></html>
"""
    config_overrides = {
        "web_spider_distance": 1,
        "web_spider_depth": 1,
        "modules": {
            "nuclei": {
                "mode": "manual",
                "concurrency": 2,
                "ratelimit": 10,
                "templates": "/tmp/.bbot_test/tools/nuclei-templates/miscellaneous/",
                "interactsh_disable": True,
                "directory_only": False,
            }
        },
    }

    def mock_args(self):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": self.test_html}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/testmultipleruns.html"}
        respond_args = {"response_data": "<html>Copyright 1984</html>"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        first_run_detect = False
        second_run_detect = False
        for e in events:
            print(e.type)
            if e.type == "FINDING":
                if "Directory listing enabled" in e.data["description"]:
                    first_run_detect = True
                elif "Copyright" in e.data["description"]:
                    second_run_detect = True
        if first_run_detect and second_run_detect:
            return True
        return False


class Nuclei_severe(HttpxMockHelper):
    additional_modules = ["httpx"]

    config_overrides = {
        "modules": {
            "nuclei": {
                "mode": "severe",
                "concurrency": 1,
                "templates": "/tmp/.bbot_test/tools/nuclei-templates/vulnerabilities/generic/generic-linux-lfi.yaml",
            }
        },
        "interactsh_disable": True,
    }

    def mock_args(self):
        expect_args = {"method": "GET", "uri": "/etc/passwd"}
        respond_args = {"response_data": "<html>root:.*:0:0:</html>"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        for e in events:
            if e.type == "VULNERABILITY":
                if "Generic Linux - Local File Inclusion" in e.data["description"]:
                    return True
        return False


class Nuclei_technology(HttpxMockHelper):
    additional_modules = ["httpx"]

    config_overrides = {
        "interactsh_disable": True,
        "modules": {"nuclei": {"mode": "technology", "concurrency": 2, "tags": "apache"}},
    }

    def __init__(self, config, bbot_scanner, bbot_httpserver, caplog, *args, **kwargs):
        self.caplog = caplog
        super().__init__(config, bbot_scanner, bbot_httpserver, *args, **kwargs)

    def mock_args(self):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {
            "response_data": "<html><Directory></Directory></html>",
            "headers": {"Server": "Apache/2.4.52 (Ubuntu)"},
        }
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        if "Using Interactsh Server" in self.caplog.text:
            return False

        for e in events:
            if e.type == "FINDING":
                if "apache" in e.data["description"]:
                    return True
        return False


class Nuclei_budget(HttpxMockHelper):
    additional_modules = ["httpx"]

    config_overrides = {
        "modules": {
            "nuclei": {
                "mode": "budget",
                "concurrency": 1,
                "tags": "spiderfoot",
                "templates": "/tmp/.bbot_test/tools/nuclei-templates/exposed-panels/spiderfoot.yaml",
                "interactsh_disable": True,
            }
        }
    }

    def mock_args(self):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "<html><title>SpiderFoot</title><p>support@spiderfoot.net</p></html>"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        for e in events:
            if e.type == "FINDING":
                if "SpiderFoot" in e.data["description"]:
                    return True
        return False


class Url_manipulation(HttpxMockHelper):
    body = """
    <html>
    <title>the title</title>
    <body>
    <p>Hello null!</p>';
    </body>
    </html>
    """

    body_match = """
    <html>
    <title>the title</title>
    <body>
    <p>Hello AAAAAAAAAAAAAA!</p>';
    </body>
    </html>
    """
    additional_modules = ["httpx"]

    def mock_args(self):
        expect_args = {"query_string": f"{self.module.rand_string}=.xml".encode()}
        respond_args = {"response_data": self.body_match}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        respond_args = {"response_data": self.body}
        self.set_expect_requests(respond_args=respond_args)

    def check_events(self, events):
        for e in events:
            if (
                e.type == "FINDING"
                and e.data["description"]
                == f"Url Manipulation: [body] Sig: [Modified URL: http://127.0.0.1:8888/?{self.module.rand_string}=.xml]"
            ):
                return True
        return False


class Naabu(HttpxMockHelper):
    def mock_args(self):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        for e in events:
            if e.type == "OPEN_TCP_PORT":
                return True
        return False


class Social(HttpxMockHelper):
    additional_modules = ["httpx", "excavate"]

    def mock_args(self):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": '<html><a href="https://discord.gg/asdf"/></html>'}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        for e in events:
            if e.type == "SOCIAL":
                if e.data["platform"] == "discord":
                    return True
        return False


class Hunt(HttpxMockHelper):
    additional_modules = ["httpx"]

    def mock_args(self):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": '<html><a href="/hackme.php?cipher=xor">ping</a></html>'}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        for e in events:
            if (
                e.type == "FINDING"
                and e.data["description"] == "Found potential INSECURE CRYPTOGRAPHY parameter [cipher]"
            ):
                return True
        return False


class Bypass403(HttpxMockHelper):
    additional_modules = ["httpx"]

    targets = ["http://127.0.0.1:8888/test"]

    def setup(self):
        self.bbot_httpserver.no_handler_status_code = 403

    def mock_args(self):
        expect_args = {"method": "GET", "uri": "/test..;/"}
        respond_args = {"response_data": "alive"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        for e in events:
            if e.type == "FINDING":
                return True
        return False


class Bypass403_aspnetcookieless(HttpxMockHelper):
    additional_modules = ["httpx"]

    targets = ["http://127.0.0.1:8888/admin.aspx"]

    def setup(self):
        self.bbot_httpserver.no_handler_status_code = 403

    def mock_args(self):
        expect_args = {"method": "GET", "uri": re.compile(r"\/\([sS]\(\w+\)\)\/.+\.aspx")}
        respond_args = {"response_data": "alive"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        for e in events:
            if e.type == "FINDING":
                return True
        return False


class Bypass403_waf(HttpxMockHelper):
    additional_modules = ["httpx"]

    targets = ["http://127.0.0.1:8888/test"]

    def setup(self):
        self.bbot_httpserver.no_handler_status_code = 403

    def mock_args(self):
        expect_args = {"method": "GET", "uri": "/test..;/"}
        respond_args = {"response_data": "The requested URL was rejected"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        for e in events:
            if e.type == "FINDING":
                return False
        return True


class Speculate_subdirectories(HttpxMockHelper):
    additional_modules = ["httpx"]
    targets = ["http://127.0.0.1:8888/subdir1/subdir2/"]

    def mock_args(self):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/subdir1/"}
        respond_args = {"response_data": "alive"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/subdir1/subdir2/"}
        respond_args = {"response_data": "alive"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        for e in events:
            if e.type == "URL_UNVERIFIED":
                if e.data == "http://127.0.0.1:8888/subdir1/":
                    return True
        return False
