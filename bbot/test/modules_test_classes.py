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
