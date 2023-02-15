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
            "response_data": "<html><head><title>BBOT is life</title></head><body><big> Contents... </big></body></html>"
        }
        self.set_expect_requests(respond_args=respond_args)

    def check_events(self, events):
        screenshots_path = self.home_dir / "scans" / "gowitness_test" / "gowitness" / "screenshots"
        screenshots = list(screenshots_path.glob("*.png"))
        if screenshots:
            return True
        return False


class Excavate(HttpxMockHelper):
    additional_modules = ["httpx"]
    targets = ["http://127.0.0.1:8888/", "test.notreal"]

    def mock_args(self):
        response_data = """
        ftp://ftp.test.notreal
        \\nhttps://www1.test.notreal
        \\x3dhttps://www2.test.notreal
        %a2https://www3.test.notreal
        \\uac20https://www4.test.notreal
        \nwww5.test.notreal
        \\x3dwww6.test.notreal
        %a2www7.test.notreal
        \\uac20www8.test.notreal
        <a src="http://www9.test.notreal">
        """
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": response_data}
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


class Badsecrets(HttpxMockHelper):
    targets = ["http://127.0.0.1:8888/", "http://127.0.0.1:8888/test.aspx", "http://127.0.0.1:8888/cookie.aspx"]

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

    def check_events(self, events):
        SecretFound = False
        IdentifyOnly = False
        CookieBasedDetection = False
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

        if SecretFound and IdentifyOnly and CookieBasedDetection:
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


class LeakIX(RequestMockHelper):
    def mock_args(self):
        self.register_uri(
            "https://leakix.net/domain/blacklanternsecurity.com",
            json={
                "Services": [
                    {
                        "event_type": "service",
                        "event_source": "HttpPlugin",
                        "event_pipeline": ["CertStream", "l9scan", "tcpid", "HttpPlugin"],
                        "event_fingerprint": "6d1f2e7ca5e9923ae691bd5ccbc6a29f4c7590907dc63317c958aafc5523fd76",
                        "ip": "2606:50c0:8000::153",
                        "host": "www.blacklanternsecurity.com",
                        "reverse": "",
                        "port": "443",
                        "mac": "",
                        "vendor": "",
                        "transport": ["tcp", "tls", "http"],
                        "protocol": "https",
                        "http": {
                            "root": "",
                            "url": "",
                            "status": 0,
                            "length": 0,
                            "header": {"content-length": "7567", "server": "GitHub.com"},
                            "title": "Welcome | Black Lantern Security",
                            "favicon_hash": "",
                        },
                        "summary": 'Connection: close\r\nContent-Length: 7567\r\nServer: GitHub.com\r\nContent-Type: text/html; charset=utf-8\r\nLast-Modified: Wed, 02 Mar 2022 18:16:15 GMT\r\nAccess-Control-Allow-Origin: *\r\nETag: "621fb46f-1d8f"\r\nexpires: Sun, 23 Oct 2022 10:32:07 GMT\r\nCache-Control: max-age=600\r\nx-proxy-cache: MISS\r\nX-GitHub-Request-Id: 080E:5274:2CE0396:3F21533:635515CF\r\nAccept-Ranges: bytes\r\nDate: Sun, 23 Oct 2022 20:46:28 GMT\r\nVia: 1.1 varnish\r\nAge: 0\r\nX-Served-By: cache-yyz4564-YYZ\r\nX-Cache: HIT\r\nX-Cache-Hits: 1\r\nX-Timer: S1666557989.582624,VS0,VE1\r\nVary: Accept-Encoding\r\nX-Fastly-Request-ID: d777ccbfc2b548eeb00cef0689cca2401789fefb\r\n\nPage title: Welcome | Black Lantern Security',
                        "time": "2022-10-23T20:46:28.514950447Z",
                        "ssl": {
                            "detected": False,
                            "enabled": True,
                            "jarm": "29d29d00029d29d00042d43d00041d2aa5ce6a70de7ba95aef77a77b00a0af",
                            "cypher_suite": "TLS_AES_128_GCM_SHA256",
                            "version": "TLSv1.3",
                            "certificate": {
                                "cn": "www.blacklanternsecurity.com",
                                "domain": ["www.blacklanternsecurity.com", "asdf.blacklanternsecurity.com"],
                                "fingerprint": "65a85fca54f3429f63aadf9aae68a2ce7c292fd7d140afe618c58bf866112fea",
                                "key_algo": "RSA",
                                "key_size": 2048,
                                "issuer_name": "R3",
                                "not_before": "2022-08-24T17:27:08Z",
                                "not_after": "2022-11-22T17:27:07Z",
                                "valid": True,
                            },
                        },
                        "ssh": {"fingerprint": "", "version": 0, "banner": "", "motd": ""},
                        "service": {
                            "credentials": {"noauth": False, "username": "", "password": "", "key": "", "raw": None},
                            "software": {
                                "name": "GitHub.com",
                                "version": "",
                                "os": "",
                                "modules": None,
                                "fingerprint": "",
                            },
                        },
                        "leak": {
                            "stage": "",
                            "type": "",
                            "severity": "",
                            "dataset": {
                                "rows": 0,
                                "files": 0,
                                "size": 0,
                                "collections": 0,
                                "infected": False,
                                "ransom_notes": None,
                            },
                        },
                        "tags": [],
                        "geoip": {
                            "continent_name": "North America",
                            "region_iso_code": "",
                            "city_name": "",
                            "country_iso_code": "US",
                            "country_name": "United States",
                            "region_name": "",
                            "location": {"lat": 37.751, "lon": -97.822},
                        },
                        "network": {
                            "organization_name": "FASTLY",
                            "asn": 54113,
                            "network": "2606:50c0:8000:0:0:0:0:0/46",
                        },
                    }
                ],
                "Leaks": None,
            },
        )

    def check_events(self, events):
        www = False
        asdf = False
        for e in events:
            if e.type == "DNS_NAME":
                if e.data == "www.blacklanternsecurity.com":
                    www = True
                elif e.data == "asdf.blacklanternsecurity.com":
                    asdf = True
        return www and asdf


class Massdns(MockHelper):
    subdomain_wordlist = tempwordlist(["www", "asdf"])
    nameserver_wordlist = tempwordlist(["8.8.8.8", "8.8.4.4", "1.1.1.1"])
    config_overrides = {"modules": {"massdns": {"wordlist": str(subdomain_wordlist)}}}

    def __init__(self, *args, **kwargs):
        with requests_mock.Mocker() as m:
            m.register_uri("GET", "https://public-dns.info/nameserver/nameservers.json", status_code=404)
            super().__init__(*args, **kwargs)

    def patch_scan(self, scan):
        scan.helpers.dns.fallback_nameservers_file = self.nameserver_wordlist

    def check_events(self, events):
        for e in events:
            if e.type == "DNS_NAME" and e == "www.blacklanternsecurity.com":
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
    # massdns can't scan localhost
    targets = ["8.8.8.8/32"]
    config_overrides = {"force_deps": True, "modules": {"masscan": {"ports": "53", "wait": 1}}}

    def check_events(self, events):
        for e in events:
            if e.type == "OPEN_TCP_PORT" and e.data == "8.8.8.8:53":
                return True
        return False


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
