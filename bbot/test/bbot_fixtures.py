import os
import sys
import pytest
import logging
import subprocess
import tldextract
from pathlib import Path
from omegaconf import OmegaConf
from pytest_httpserver import HTTPServer
import pytest_httpserver

from werkzeug.wrappers import Request


class SubstringRequestMatcher(pytest_httpserver.httpserver.RequestMatcher):
    def match_data(self, request: Request) -> bool:
        if self.data is None:
            return True
        return self.data in request.data


pytest_httpserver.httpserver.RequestMatcher = SubstringRequestMatcher

from bbot.modules.telerik import telerik

telerik.telerikVersions = ["2014.2.724", "2014.3.1024", "2015.1.204"]
telerik.DialogHandlerUrls = [
    "Admin/ServerSide/Telerik.Web.UI.DialogHandler.aspx",
    "App_Master/Telerik.Web.UI.DialogHandler.aspx",
    "AsiCommon/Controls/ContentManagement/ContentDesigner/Telerik.Web.UI.DialogHandler.aspx",
]

test_config = OmegaConf.load(Path(__file__).parent / "test.conf")
if test_config.get("debug", False):
    os.environ["BBOT_DEBUG"] = "True"
os.environ["BBOT_TESTING"] = "True"

from .bbot_fixtures import *  # noqa: F401
import bbot.core.logger  # noqa: F401
from bbot.core.errors import *  # noqa: F401

log = logging.getLogger(f"bbot.test")

# silence pytest_httpserver
log = logging.getLogger("werkzeug")
log.setLevel(logging.CRITICAL)

# silence stdout
root_logger = logging.getLogger()
for h in root_logger.handlers:
    h.addFilter(lambda x: x.levelname not in ("STDOUT", "TRACE"))

tldextract.extract("www.evilcorp.com")

log = logging.getLogger(f"bbot.test.fixtures")


@pytest.fixture
def patch_commands():
    import subprocess

    sample_output = [
        # massdns
        """{"name":"www.blacklanternsecurity.com.","type":"A","class":"IN","status":"NOERROR","rx_ts":1659985004071981831,"data":{"answers":[{"ttl":3580,"type":"CNAME","class":"IN","name":"www.blacklanternsecurity.com.","data":"blacklanternsecurity.github.io."},{"ttl":3580,"type":"A","class":"IN","name":"blacklanternsecurity.github.io.","data":"185.199.108.153"},{"ttl":3580,"type":"A","class":"IN","name":"blacklanternsecurity.github.io.","data":"185.199.109.153"},{"ttl":3580,"type":"A","class":"IN","name":"blacklanternsecurity.github.io.","data":"185.199.110.153"},{"ttl":3580,"type":"A","class":"IN","name":"blacklanternsecurity.github.io.","data":"185.199.111.153"}]},"flags":["rd","ra"],"resolver":"8.8.8.8:53"}""",
        # httpx
        """{"timestamp":"2022-11-14T12:15:47.152132075-05:00","hash":{"body_md5":"84238dfc8092e5d9c0dac8ef93371a07","body_mmh3":"-1139337416","body_sha256":"ea8fac7c65fb589b0d53560f5251f74f9e9b243478dcb6b3ea79b5e36449c8d9","body_simhash":"9899951357530060719","header_md5":"fbe962f8536d2df0ee25efbf3ba8ba6e","header_mmh3":"1030635337","header_sha256":"2bec212a3ad091763a68ed40e6b004a546036c5b5e0ec02713f8625ab573e9ab","header_simhash":"15614709017155972447"},"port":"80","url":"http://example.com:80","input":"http://example.com:80","title":"Example Domain","scheme":"http","webserver":"ECS (agb/A434)","body":"\u003c!doctype html\u003e\n\u003chtml\u003e\n\u003chead\u003e\n    \u003ctitle\u003eExample Domain\u003c/title\u003e\n\n    \u003cmeta charset=\"utf-8\" /\u003e\n    \u003cmeta http-equiv=\"Content-type\" content=\"text/html; charset=utf-8\" /\u003e\n    \u003cmeta name=\"viewport\" content=\"width=device-width, initial-scale=1\" /\u003e\n    \u003cstyle type=\"text/css\"\u003e\n    body {\n        background-color: #f0f0f2;\n        margin: 0;\n        padding: 0;\n        font-family: -apple-system, system-ui, BlinkMacSystemFont, \"Segoe UI\", \"Open Sans\", \"Helvetica Neue\", Helvetica, Arial, sans-serif;\n        \n    }\n    div {\n        width: 600px;\n        margin: 5em auto;\n        padding: 2em;\n        background-color: #fdfdff;\n        border-radius: 0.5em;\n        box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);\n    }\n    a:link, a:visited {\n        color: #38488f;\n        text-decoration: none;\n    }\n    @media (max-width: 700px) {\n        div {\n            margin: 0 auto;\n            width: auto;\n        }\n    }\n    \u003c/style\u003e    \n\u003c/head\u003e\n\n\u003cbody\u003e\n\u003cdiv\u003e\n    \u003ch1\u003eExample Domain\u003c/h1\u003e\n    \u003cp\u003eThis domain is for use in illustrative examples in documents. You may use this\n    domain in literature without prior coordination or asking for permission.\u003c/p\u003e\n    \u003cp\u003e\u003ca href=\"https://www.iana.org/domains/example\"\u003eMore information...\u003c/a\u003e\u003c/p\u003e\n\u003c/div\u003e\n\u003c/body\u003e\n\u003c/html\u003e\n","content_type":"text/html","method":"GET","host":"93.184.216.34","path":"/","header":{"age":"551615","cache_control":"max-age=604800","content_type":"text/html; charset=UTF-8","date":"Mon, 14 Nov 2022 17:15:47 GMT","etag":"\"3147526947+gzip\"","expires":"Mon, 21 Nov 2022 17:15:47 GMT","last_modified":"Thu, 17 Oct 2019 07:18:26 GMT","server":"ECS (agb/A434)","vary":"Accept-Encoding","x_cache":"HIT"},"raw_header":"HTTP/1.1 200 OK\r\nConnection: close\r\nAge: 551615\r\nCache-Control: max-age=604800\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Mon, 14 Nov 2022 17:15:47 GMT\r\nEtag: \"3147526947+gzip\"\r\nExpires: Mon, 21 Nov 2022 17:15:47 GMT\r\nLast-Modified: Thu, 17 Oct 2019 07:18:26 GMT\r\nServer: ECS (agb/A434)\r\nVary: Accept-Encoding\r\nX-Cache: HIT\r\n\r\n","request":"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Xenu Link Sleuth/1.3.8\r\nAccept-Charset: utf-8\r\nAccept-Encoding: gzip\r\n\r\n","time":"99.670794ms","a":["93.184.216.34","2606:2800:220:1:248:1893:25c8:1946"],"words":298,"lines":47,"status_code":200,"content_length":1256,"failed":false}""",
        # nuclei
        """{"template":"technologies/tech-detect.yaml","template-url":"https://github.com/projectdiscovery/nuclei-templates/blob/master/technologies/tech-detect.yaml","template-id":"tech-detect","info":{"name":"Wappalyzer Technology Detection","author":["hakluke"],"tags":["tech"],"reference":null,"severity":"info"},"matcher-name":"caddy","type":"http","host":"https://api.publicapis.org/health","matched-at":"https://api.publicapis.org:443/health","ip":"138.197.231.124","timestamp":"2022-04-15T17:09:01.021589723-04:00","curl-command":"curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2226.0 Safari/537.36' 'https://api.publicapis.org/health'","matcher-status":true,"matched-line":null}""",
        # naabu
        """{"ip":"8.8.8.8","port":443,"timestamp":"2022-08-03T16:01:15.684442081Z"}"""
        # ffuf
        """{"input":{"FUZZ":"L2luZGV4Lmh0bWw="},"position":1,"status":200,"length":1256,"words":298,"lines":47,"content-type":"text/html;charset=UTF-8","redirectlocation":"","url":"http://example.com:80//index.html","duration":101243249,"resultfile":"","host":"example.com:80"}""",
        "https://api.publicapis.org:443/health",
        # open port
        "api.publicapis.org:443",
        # host
        "api.publicapis.org",
        # url
        "https://8.8.8.8",
    ]

    def patch_scan_commands(scanner):
        def run(*args, **kwargs):
            log.debug(f"helpers.command.run(args={args}, kwargs={kwargs})")
            text = kwargs.get("text", True)
            return subprocess.run(["echo", "\n".join(sample_output)], text=text, stdout=subprocess.PIPE)

        def run_live(*args, **kwargs):
            log.debug(f"helpers.command.run_live(args={args}, kwargs={kwargs})")
            for line in sample_output:
                yield line

        from bbot.core.helpers.command import run as old_run, run_live as old_run_live

        scanner.helpers.run = run
        scanner.helpers.run_live = run_live
        return old_run, old_run_live

    return patch_scan_commands


@pytest.fixture
def bbot_scanner():
    from bbot.scanner import Scanner

    return Scanner


@pytest.fixture
def neograph(monkeypatch, helpers):
    helpers.depsinstaller.pip_install(["py2neo"])

    class NeoGraph:
        def __init__(self, *args, **kwargs):
            pass

        def merge(self, *args, **kwargs):
            return True

    import py2neo

    monkeypatch.setattr(py2neo, "Graph", NeoGraph)
    from bbot.db.neo4j import Neo4j

    return Neo4j(uri="bolt://127.0.0.1:1111")


@pytest.fixture
def patch_ansible(monkeypatch):
    from ansible_runner.interface import run

    class AnsibleRunnerResult:
        status = "successful"
        rc = 0
        events = []

    def ansible_run(*args, **kwargs):
        return AnsibleRunnerResult()

    from bbot.core.helpers.depsinstaller import installer

    ensure_root = installer.DepsInstaller.ensure_root

    def patch_scan_ansible(scanner):
        monkeypatch.setattr(installer, "run", ansible_run)
        monkeypatch.setattr(scanner.helpers.depsinstaller, "ensure_root", lambda *args, **kwargs: None)
        return run, ensure_root

    return patch_scan_ansible


@pytest.fixture
def scan(monkeypatch, patch_ansible, patch_commands, bbot_config):
    from bbot.scanner import Scanner

    bbot_scan = Scanner("127.0.0.1", modules=["ipneighbor"], config=bbot_config)
    patch_commands(bbot_scan)
    patch_ansible(bbot_scan)
    bbot_scan.status = "RUNNING"

    fallback_nameservers_file = bbot_scan.helpers.bbot_home / "fallback_nameservers.txt"
    with open(fallback_nameservers_file, "w") as f:
        f.write("8.8.8.8\n")
    monkeypatch.setattr(bbot_scan.helpers.dns, "fallback_nameservers_file", fallback_nameservers_file)

    return bbot_scan


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
        localhost = scan.make_event("127.0.0.1", source=scan.root_event)
        ipv4 = scan.make_event("8.8.8.8", source=scan.root_event)
        netv4 = scan.make_event("8.8.8.8/30", source=scan.root_event)
        ipv6 = scan.make_event("2001:4860:4860::8888", source=scan.root_event)
        netv6 = scan.make_event("2001:4860:4860::8888/126", source=scan.root_event)
        domain = scan.make_event("publicAPIs.org", source=scan.root_event)
        subdomain = scan.make_event("api.publicAPIs.org", source=scan.root_event)
        email = scan.make_event("bob@evilcorp.co.uk", "EMAIL_ADDRESS", source=scan.root_event)
        open_port = scan.make_event("api.publicAPIs.org:443", source=scan.root_event)
        protocol = scan.make_event(
            {"host": "api.publicAPIs.org", "port": 443, "protocol": "HTTP"}, "PROTOCOL", source=scan.root_event
        )
        ipv4_open_port = scan.make_event("8.8.8.8:443", source=scan.root_event)
        ipv6_open_port = scan.make_event("[2001:4860:4860::8888]:443", "OPEN_TCP_PORT", source=scan.root_event)
        url_unverified = scan.make_event("https://api.publicAPIs.org:443/hellofriend", source=scan.root_event)
        ipv4_url_unverified = scan.make_event("https://8.8.8.8:443/hellofriend", source=scan.root_event)
        ipv6_url_unverified = scan.make_event("https://[2001:4860:4860::8888]:443/hellofriend", source=scan.root_event)
        url = scan.make_event(
            "https://api.publicAPIs.org:443/hellofriend", "URL", tags=["status-200"], source=scan.root_event
        )
        ipv4_url = scan.make_event(
            "https://8.8.8.8:443/hellofriend", "URL", tags=["status-200"], source=scan.root_event
        )
        ipv6_url = scan.make_event(
            "https://[2001:4860:4860::8888]:443/hellofriend", "URL", tags=["status-200"], source=scan.root_event
        )
        url_hint = scan.make_event("https://api.publicAPIs.org:443/hello.ash", "URL_HINT", source=scan.root_event)
        vulnerability = scan.make_event(
            {"host": "evilcorp.com", "severity": "INFO", "description": "asdf"},
            "VULNERABILITY",
            source=scan.root_event,
        )
        finding = scan.make_event({"host": "evilcorp.com", "description": "asdf"}, "FINDING", source=scan.root_event)
        vhost = scan.make_event({"host": "evilcorp.com", "vhost": "www.evilcorp.com"}, "VHOST", source=scan.root_event)
        http_response = scan.make_event(httpx_response, "HTTP_RESPONSE", source=scan.root_event)
        storage_bucket = scan.make_event(
            {"name": "storage", "url": "https://storage.blob.core.windows.net"},
            "STORAGE_BUCKET",
            source=scan.root_event,
        )
        emoji = scan.make_event("💩", "WHERE_IS_YOUR_GOD_NOW", source=scan.root_event)

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
        e.make_in_scope()

    return bbot_events


@pytest.fixture
def agent(monkeypatch, websocketapp, bbot_config):
    from bbot import agent
    from bbot.modules.output.websocket import Websocket

    monkeypatch.setattr(Websocket, "send", lambda *args, **kwargs: True)

    test_agent = agent.Agent(bbot_config)
    test_agent.setup()
    monkeypatch.setattr(test_agent, "ws", websocketapp())
    return test_agent


@pytest.fixture
def websocketapp():
    class WebSocketApp:
        def __init__(*args, **kwargs):
            return

        def send(self, message):
            assert type(message) == str

        def run_forever(*args, **kwargs):
            return False

        def close(self):
            return

    return WebSocketApp


# bbot config
from bbot import config as default_config

test_config = OmegaConf.load(Path(__file__).parent / "test.conf")
test_config = OmegaConf.merge(default_config, test_config)


@pytest.fixture
def bbot_config():
    return test_config


from bbot.modules import module_loader

available_modules = list(module_loader.configs(type="scan"))
available_output_modules = list(module_loader.configs(type="output"))
available_internal_modules = list(module_loader.configs(type="internal"))


@pytest.fixture(autouse=True)
def install_all_python_deps():
    deps_pip = set()
    for module in module_loader.preloaded().values():
        deps_pip.update(set(module.get("deps", {}).get("pip", [])))
    subprocess.run([sys.executable, "-m", "pip", "install"] + list(deps_pip))


@pytest.fixture
def bbot_httpserver():
    server = HTTPServer(host="127.0.0.1", port=8888)
    server.start()

    yield server

    server.clear()
    if server.is_running():
        server.stop()

    # this is to check if the client has made any request where no
    # `assert_request` was called on it from the test

    server.check_assertions()
    server.clear()
