import os  # noqa
import sys  # noqa
import pytest
import shutil  # noqa
import asyncio  # noqa
import logging
import tldextract
import pytest_httpserver
from pathlib import Path
from omegaconf import OmegaConf  # noqa

from werkzeug.wrappers import Request

from bbot.errors import *  # noqa: F401
from bbot.core import CORE
from bbot.scanner import Preset
from bbot.core.helpers.misc import mkdir, rand_string
from bbot.core.helpers.async_helpers import get_event_loop


log = logging.getLogger("bbot.test.fixtures")


bbot_test_dir = Path("/tmp/.bbot_test")
mkdir(bbot_test_dir)


DEFAULT_PRESET = Preset()

available_modules = list(DEFAULT_PRESET.module_loader.configs(type="scan"))
available_output_modules = list(DEFAULT_PRESET.module_loader.configs(type="output"))
available_internal_modules = list(DEFAULT_PRESET.module_loader.configs(type="internal"))


def tempwordlist(content):
    filename = bbot_test_dir / f"{rand_string(8)}"
    with open(filename, "w", errors="ignore") as f:
        for c in content:
            line = f"{c}\n"
            f.write(line)
    return filename


def tempapkfile():
    current_dir = Path(__file__).parent
    with open(current_dir / "owasp_mastg.apk", "rb") as f:
        apk_file = f.read()
    return apk_file


@pytest.fixture
def clean_default_config(monkeypatch):
    clean_config = OmegaConf.merge(
        CORE.files_config.get_default_config(), {"modules": DEFAULT_PRESET.module_loader.configs()}
    )
    with monkeypatch.context() as m:
        m.setattr("bbot.core.core.DEFAULT_CONFIG", clean_config)
        yield


class SubstringRequestMatcher(pytest_httpserver.httpserver.RequestMatcher):
    def match_data(self, request: Request) -> bool:
        if self.data is None:
            return True
        return self.data in request.data


pytest_httpserver.httpserver.RequestMatcher = SubstringRequestMatcher

# silence pytest_httpserver
log = logging.getLogger("werkzeug")
log.setLevel(logging.CRITICAL)

tldextract.extract("www.evilcorp.com")


@pytest.fixture
def bbot_scanner():
    from bbot.scanner import Scanner

    return Scanner


@pytest.fixture
def scan():
    from bbot.scanner import Scanner

    bbot_scan = Scanner("127.0.0.1", modules=["ipneighbor"])
    yield bbot_scan

    loop = get_event_loop()
    loop.run_until_complete(bbot_scan._cleanup())


@pytest.fixture
def helpers(scan):
    return scan.helpers


httpx_response = {
    "timestamp": "2022-11-14T12:14:27.377566416-05:00",
    "hash": {
        "body_md5": "84238dfc8092e5d9c0dac8ef93371a07",
        "body_mmh3": "-1139337416",
        "body_sha256": "ea8fac7c65fb589b0d53560f5251f74f9e9b243478dcb6b3ea79b5e36449c8d9",
        "body_simhash": "9899951357530060719",
        "header_md5": "6e483c85c3b9b96f0e33d84237ca651e",
        "header_mmh3": "-957156428",
        "header_sha256": "5a809d8a53aded843179237365bb6dd069fba75ff8603ac2f6dc6c05d6bf0e76",
        "header_simhash": "15614709017155972941",
    },
    "port": "80",
    "url": "http://example.com:80",
    "input": "http://example.com:80",
    "title": "Example Domain",
    "scheme": "http",
    "webserver": "ECS (agb/A445)",
    "body": '<!doctype html>\n<html>\n<head>\n    <title>Example Domain</title>\n\n    <meta charset="utf-8" />\n    <meta http-equiv="Content-type" content="text/html; charset=utf-8" />\n    <meta name="viewport" content="width=device-width, initial-scale=1" />\n    <style type="text/css">\n    body {\n        background-color: #f0f0f2;\n        margin: 0;\n        padding: 0;\n        font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;\n        \n    }\n    div {\n        width: 600px;\n        margin: 5em auto;\n        padding: 2em;\n        background-color: #fdfdff;\n        border-radius: 0.5em;\n        box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);\n    }\n    a:link, a:visited {\n        color: #38488f;\n        text-decoration: none;\n    }\n    @media (max-width: 700px) {\n        div {\n            margin: 0 auto;\n            width: auto;\n        }\n    }\n    </style>    \n</head>\n\n<body>\n<div>\n    <h1>Example Domain</h1>\n    <p>This domain is for use in illustrative examples in documents. You may use this\n    domain in literature without prior coordination or asking for permission.</p>\n    <p><a href="https://www.iana.org/domains/example">More information...</a></p>\n</div>\n</body>\n</html>\n',
    "content_type": "text/html",
    "method": "GET",
    "host": "93.184.216.34",
    "path": "/",
    "header": {
        "age": "526111",
        "cache_control": "max-age=604800",
        "content_type": "text/html; charset=UTF-8",
        "date": "Mon, 14 Nov 2022 17:14:27 GMT",
        "etag": '"3147526947+ident+gzip"',
        "expires": "Mon, 21 Nov 2022 17:14:27 GMT",
        "last_modified": "Thu, 17 Oct 2019 07:18:26 GMT",
        "server": "ECS (agb/A445)",
        "vary": "Accept-Encoding",
        "x_cache": "HIT",
    },
    "raw_header": 'HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 526111\r\nCache-Control: max-age=604800\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Mon, 14 Nov 2022 17:14:27 GMT\r\nEtag: "3147526947+ident+gzip"\r\nExpires: Mon, 21 Nov 2022 17:14:27 GMT\r\nLast-Modified: Thu, 17 Oct 2019 07:18:26 GMT\r\nServer: ECS (agb/A445)\r\nVary: Accept-Encoding\r\nX-Cache: HIT\r\n\r\n',
    "request": "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (SymbianOS/9.1; U; de) AppleWebKit/413 (KHTML, like Gecko) Safari/413\r\nAccept-Charset: utf-8\r\nAccept-Encoding: gzip\r\n\r\n",
    "time": "112.128324ms",
    "a": ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"],
    "words": 298,
    "lines": 47,
    "status_code": 200,
    "content_length": 1256,
    "failed": False,
}


@pytest.fixture
def events(scan):
    class bbot_events:
        localhost = scan.make_event("127.0.0.1", parent=scan.root_event)
        ipv4 = scan.make_event("8.8.8.8", parent=scan.root_event)
        netv4 = scan.make_event("8.8.8.8/30", parent=scan.root_event)
        ipv6 = scan.make_event("2001:4860:4860::8888", parent=scan.root_event)
        netv6 = scan.make_event("2001:4860:4860::8888/126", parent=scan.root_event)
        domain = scan.make_event("publicAPIs.org", parent=scan.root_event)
        subdomain = scan.make_event("api.publicAPIs.org", parent=scan.root_event)
        email = scan.make_event("bob@evilcorp.co.uk", "EMAIL_ADDRESS", parent=scan.root_event)
        open_port = scan.make_event("api.publicAPIs.org:443", parent=scan.root_event)
        protocol = scan.make_event(
            {"host": "api.publicAPIs.org", "port": 443, "protocol": "HTTP"}, "PROTOCOL", parent=scan.root_event
        )
        ipv4_open_port = scan.make_event("8.8.8.8:443", parent=scan.root_event)
        ipv6_open_port = scan.make_event("[2001:4860:4860::8888]:443", "OPEN_TCP_PORT", parent=scan.root_event)
        url_unverified = scan.make_event("https://api.publicAPIs.org:443/hellofriend", parent=scan.root_event)
        ipv4_url_unverified = scan.make_event("https://8.8.8.8:443/hellofriend", parent=scan.root_event)
        ipv6_url_unverified = scan.make_event("https://[2001:4860:4860::8888]:443/hellofriend", parent=scan.root_event)
        url = scan.make_event(
            "https://api.publicAPIs.org:443/hellofriend", "URL", tags=["status-200"], parent=scan.root_event
        )
        ipv4_url = scan.make_event(
            "https://8.8.8.8:443/hellofriend", "URL", tags=["status-200"], parent=scan.root_event
        )
        ipv6_url = scan.make_event(
            "https://[2001:4860:4860::8888]:443/hellofriend", "URL", tags=["status-200"], parent=scan.root_event
        )
        url_hint = scan.make_event("https://api.publicAPIs.org:443/hello.ash", "URL_HINT", parent=url)
        vulnerability = scan.make_event(
            {"host": "evilcorp.com", "severity": "INFO", "description": "asdf"},
            "VULNERABILITY",
            parent=scan.root_event,
        )
        finding = scan.make_event({"host": "evilcorp.com", "description": "asdf"}, "FINDING", parent=scan.root_event)
        vhost = scan.make_event({"host": "evilcorp.com", "vhost": "www.evilcorp.com"}, "VHOST", parent=scan.root_event)
        http_response = scan.make_event(httpx_response, "HTTP_RESPONSE", parent=scan.root_event)
        storage_bucket = scan.make_event(
            {"name": "storage", "url": "https://storage.blob.core.windows.net"},
            "STORAGE_BUCKET",
            parent=scan.root_event,
        )
        emoji = scan.make_event("💩", "WHERE_IS_YOUR_GOD_NOW", parent=scan.root_event)

    bbot_events.all = [  # noqa: F841
        bbot_events.localhost,
        bbot_events.ipv4,
        bbot_events.netv4,
        bbot_events.ipv6,
        bbot_events.netv6,
        bbot_events.domain,
        bbot_events.subdomain,
        bbot_events.email,
        bbot_events.open_port,
        bbot_events.protocol,
        bbot_events.ipv4_open_port,
        bbot_events.ipv6_open_port,
        bbot_events.url_unverified,
        bbot_events.ipv4_url_unverified,
        bbot_events.ipv6_url_unverified,
        bbot_events.url,
        bbot_events.ipv4_url,
        bbot_events.ipv6_url,
        bbot_events.url_hint,
        bbot_events.vulnerability,
        bbot_events.finding,
        bbot_events.vhost,
        bbot_events.http_response,
        bbot_events.storage_bucket,
        bbot_events.emoji,
    ]

    for e in bbot_events.all:
        e.scope_distance = 0

    return bbot_events


# @pytest.fixture(scope="session", autouse=True)
# def install_all_python_deps():
#     deps_pip = set()
#     for module in DEFAULT_PRESET.module_loader.preloaded().values():
#         deps_pip.update(set(module.get("deps", {}).get("pip", [])))

#     constraint_file = tempwordlist(get_python_constraints())

#     subprocess.run([sys.executable, "-m", "pip", "install", "--constraint", constraint_file] + list(deps_pip))
