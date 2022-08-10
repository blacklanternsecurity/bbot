import pytest
import urllib3
import requests
import tldextract
from pathlib import Path
from omegaconf import OmegaConf

# make the necessary web requests before nuking them to high heaven
example_url = "https://api.publicapis.org/health"
http = urllib3.PoolManager()
urllib_response = http.request("GET", example_url)
requests_response = requests.get(example_url)
tldextract.extract("www.evilcorp.com")


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
def neuter_ansible(monkeypatch):
    from ansible_runner.interface import run

    class AnsibleRunnerResult:
        status = "successful"
        rc = 0
        events = []

    def ansible_run(*args, **kwargs):
        module = kwargs.get("module", "")
        if module != "pip":
            return AnsibleRunnerResult()
        else:
            return run(*args, **kwargs)

    from bbot.core.helpers.depsinstaller import installer

    ensure_root = installer.DepsInstaller.ensure_root

    monkeypatch.setattr(installer, "run", ansible_run)
    monkeypatch.setattr(installer.DepsInstaller, "ensure_root", lambda *args, **kwargs: None)

    return run, ensure_root


@pytest.fixture
def bbot_config():
    from bbot import config as default_config

    test_config = OmegaConf.load(Path(__file__).parent / "test.conf")
    config = OmegaConf.merge(default_config, test_config)
    return config


@pytest.fixture
def scan(neuter_ansible, patch_requests, patch_commands, bbot_config):
    from bbot.scanner import Scanner

    bbot_scan = Scanner("127.0.0.1", modules=["ipneighbor"], config=bbot_config)
    bbot_scan.status = "RUNNING"
    return bbot_scan


@pytest.fixture
def helpers(scan):
    return scan.helpers


httpx_response = {
    "timestamp": "2022-06-29T09:56:19.927240577-04:00",
    "request": "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.35 Safari/537.36\r\nAccept-Charset: utf-8\r\nAccept-Encoding: gzip\r\n\r\n",
    "response-header": 'HTTP/1.1 200 OK\r\nConnection: close\r\nAccept-Ranges: bytes\r\nAge: 557710\r\nCache-Control: max-age=604800\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Wed, 29 Jun 2022 13:56:16 GMT\r\nEtag: "3147526947"\r\nExpires: Wed, 06 Jul 2022 13:56:16 GMT\r\nLast-Modified: Thu, 17 Oct 2019 07:18:26 GMT\r\nServer: ECS (agb/A438)\r\nVary: Accept-Encoding\r\nX-Cache: HIT\r\n\r\n',
    "scheme": "http",
    "port": "80",
    "path": "/",
    "url": "http://example.com:80",
    "input": "http://example.com",
    "title": "Example Domain",
    "webserver": "ECS (agb/A438)",
    "response-body": '<!doctype html>\n<html>\n<head>\n    <title>Example Domain</title>\n\n    <meta charset="utf-8" />\n    <meta http-equiv="Content-type" content="text/html; charset=utf-8" />\n    <meta name="viewport" content="width=device-width, initial-scale=1" />\n    <style type="text/css">\n    body {\n        background-color: #f0f0f2;\n        margin: 0;\n        padding: 0;\n        font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;\n        \n    }\n    div {\n        width: 600px;\n        margin: 5em auto;\n        padding: 2em;\n        background-color: #fdfdff;\n        border-radius: 0.5em;\n        box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);\n    }\n    a:link, a:visited {\n        color: #38488f;\n        text-decoration: none;\n    }\n    @media (max-width: 700px) {\n        div {\n            margin: 0 auto;\n            width: auto;\n        }\n    }\n    </style>    \n</head>\n\n<body>\n<div>\n    <h1>Example Domain</h1>\n    <p>This domain is for use in illustrative examples in documents. You may use this\n    domain in literature without prior coordination or asking for permission.</p>\n    <p><a href="https://www.iana.org/domains/example">More information...</a></p>\n</div>\n</body>\n</html>\n',
    "content-type": "text/html",
    "method": "GET",
    "host": "93.184.216.34",
    "content-length": 1256,
    "status-code": 200,
    "response-time": "95.343985ms",
    "failed": False,
    "hashes": {
        "body-md5": "84238dfc8092e5d9c0dac8ef93371a07",
        "body-mmh3": "-1139337416",
        "body-sha256": "ea8fac7c65fb589b0d53560f5251f74f9e9b243478dcb6b3ea79b5e36449c8d9",
        "body-simhash": "9899951357530060719",
        "header-md5": "99b650ea40a9e95550d7540996b67b60",
        "header-mmh3": "1831947040",
        "header-sha256": "eecbd4d9798c44295df0c5f2beebd939e7e51d9c6c16842dd73be83273f406bd",
        "header-simhash": "15614709017155964779",
    },
    "lines": 47,
    "words": 298,
}


@pytest.fixture
def events(scan):
    class bbot_events:
        localhost = scan.make_event("127.0.0.1", dummy=True)
        ipv4 = scan.make_event("8.8.8.8", dummy=True)
        netv4 = scan.make_event("8.8.8.8/30", dummy=True)
        ipv6 = scan.make_event("2001:4860:4860::8888", dummy=True)
        netv6 = scan.make_event("2001:4860:4860::8888/126", dummy=True)
        domain = scan.make_event("publicAPIs.org", dummy=True)
        subdomain = scan.make_event("api.publicAPIs.org", dummy=True)
        email = scan.make_event("bob@evilcorp.co.uk", "EMAIL_ADDRESS", dummy=True)
        open_port = scan.make_event("api.publicAPIs.org:443", dummy=True)
        protocol = scan.make_event({"host": "api.publicAPIs.org:443", "protocol": "HTTP"}, "PROTOCOL", dummy=True)
        ipv4_open_port = scan.make_event("8.8.8.8:443", dummy=True)
        ipv6_open_port = scan.make_event("[2001:4860:4860::8888]:443", "OPEN_TCP_PORT", dummy=True)
        url_unverified = scan.make_event("https://api.publicAPIs.org:443/hellofriend", dummy=True)
        ipv4_url_unverified = scan.make_event("https://8.8.8.8:443/hellofriend", dummy=True)
        ipv6_url_unverified = scan.make_event("https://[2001:4860:4860::8888]:443/hellofriend", dummy=True)
        url = scan.make_event("https://api.publicAPIs.org:443/hellofriend", "URL", dummy=True)
        ipv4_url = scan.make_event("https://8.8.8.8:443/hellofriend", "URL", dummy=True)
        ipv6_url = scan.make_event("https://[2001:4860:4860::8888]:443/hellofriend", "URL", dummy=True)
        url_hint = scan.make_event("https://api.publicAPIs.org:443/hello.ash", "URL_HINT", dummy=True)
        vulnerability = scan.make_event(
            {"host": "evilcorp.com", "severity": "INFO", "description": "asdf"}, "VULNERABILITY", dummy=True
        )
        finding = scan.make_event({"host": "evilcorp.com", "description": "asdf"}, "FINDING", dummy=True)
        vhost = scan.make_event({"host": "evilcorp.com", "vhost": "www.evilcorp.com"}, "VHOST", dummy=True)
        http_response = scan.make_event(httpx_response, "HTTP_RESPONSE", dummy=True)
        emoji = scan.make_event("💩", "WHERE_IS_YOUR_GOD_NOW", dummy=True)

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
        bbot_events.emoji,
    ]

    for e in bbot_events.all:
        e.make_in_scope()

    return bbot_events


@pytest.fixture
def patch_requests(monkeypatch):
    from bbot.core.helpers.web import request, download

    monkeypatch.setattr("urllib3.connectionpool.HTTPConnectionPool.urlopen", lambda *args, **kwargs: urllib_response)
    monkeypatch.setattr("urllib3.poolmanager.PoolManager.urlopen", lambda *args, **kwargs: urllib_response)
    monkeypatch.setattr("requests.adapters.HTTPAdapter.send", lambda *args, **kwargs: requests_response)
    monkeypatch.setattr("bbot.core.helpers.web.request", lambda *args, **kwargs: requests_response)
    current_dir = Path(__file__).resolve().parent
    downloaded_file = current_dir / "test_output.json"
    monkeypatch.setattr("bbot.core.helpers.web.download", lambda *args, **kwargs: downloaded_file)
    return request, download


@pytest.fixture
def patch_commands(monkeypatch):
    import subprocess

    sample_output = [
        # massdns
        """{"name":"www.blacklanternsecurity.com.","type":"A","class":"IN","status":"NOERROR","rx_ts":1659985004071981831,"data":{"answers":[{"ttl":3580,"type":"CNAME","class":"IN","name":"www.blacklanternsecurity.com.","data":"blacklanternsecurity.github.io."},{"ttl":3580,"type":"A","class":"IN","name":"blacklanternsecurity.github.io.","data":"185.199.108.153"},{"ttl":3580,"type":"A","class":"IN","name":"blacklanternsecurity.github.io.","data":"185.199.109.153"},{"ttl":3580,"type":"A","class":"IN","name":"blacklanternsecurity.github.io.","data":"185.199.110.153"},{"ttl":3580,"type":"A","class":"IN","name":"blacklanternsecurity.github.io.","data":"185.199.111.153"}]},"flags":["rd","ra"],"resolver":"8.8.8.8:53"}""",
        # httpx
        """{"timestamp":"2022-04-15T17:08:29.436778586-04:00","request":"GET /health HTTP/1.1\\r\\nHost: api.publicapis.org\\r\\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36\\r\\nAccept-Charset: utf-8\\r\\nAccept-Encoding: gzip\\r\\n\\r\\n","response-header":"HTTP/1.1 200 OK\\r\\nConnection: close\\r\\nContent-Length: 15\\r\\nContent-Type: text/plain; charset=utf-8\\r\\nDate: Fri, 15 Apr 2022 21:08:29 GMT\\r\\nServer: Caddy\\r\\nX-Rate-Limit-Duration: 1\\r\\nX-Rate-Limit-Limit: 10.00\\r\\nX-Rate-Limit-Request-Forwarded-For: 50.240.76.25\\r\\nX-Rate-Limit-Request-Remote-Addr: 172.17.0.1:32910\\r\\n\\r\\n","scheme":"https","port":"443","path":"/health","body-sha256":"6c63d4b385b07fe0e09a8a1f95b826e8a7d0401dfd12d649fe7c64b8a785023e","header-sha256":"161187846622dc97219392ab70195f4a477457e55dadf4b39f1b6c734e396120","url":"https://api.publicapis.org:443/health","input":"https://api.publicapis.org/health","webserver":"Caddy","response-body":"{\\"alive\\": true}","content-type":"text/plain","method":"GET","host":"138.197.231.124","content-length":15,"status-code":200,"response-time":"412.587433ms","failed":false,"lines":1,"words":2}""",
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

    def run(*args, **kwargs):
        text = kwargs.get("text", True)
        return subprocess.run(["echo", "\n".join(sample_output)], text=text, stdout=subprocess.PIPE)

    def run_live(*args, **kwargs):
        for line in sample_output:
            yield line

    from bbot.core.helpers.command import run as old_run, run_live as old_run_live

    monkeypatch.setattr("bbot.core.helpers.command.run", run)
    monkeypatch.setattr("bbot.core.helpers.command.run_live", run_live)

    return old_run, old_run_live


@pytest.fixture
def agent(monkeypatch):
    class WebSocketApp:
        def __init__(*args, **kwargs):
            return

        def send(self, message):
            assert type(message) == str

        def run_forever(*args, **kwargs):
            return False

        def close(self):
            return

    from bbot import agent
    from bbot.modules.output.websocket import Websocket

    monkeypatch.setattr(Websocket, "send", lambda *args, **kwargs: True)

    test_agent = agent.Agent({"agent_url": "test", "agent_token": "test"})
    test_agent.setup()
    monkeypatch.setattr(test_agent, "ws", WebSocketApp())
    return test_agent
