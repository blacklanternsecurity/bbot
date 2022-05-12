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
def config():
    from bbot import config as default_config

    test_config = OmegaConf.load(Path(__file__).parent / "test.conf")
    config = OmegaConf.merge(default_config, test_config)
    return config


@pytest.fixture
def scan(neuter_ansible, patch_requests, patch_commands, config):
    from bbot.scanner import Scanner

    bbot_scan = Scanner("127.0.0.1", modules=["dnsresolve"], config=config)
    return bbot_scan


@pytest.fixture
def helpers(scan):
    return scan.helpers


@pytest.fixture
def events(scan):
    class bbot_events:
        ipv4 = scan.make_event("8.8.8.8", dummy=True)
        netv4 = scan.make_event("8.8.8.8/30", dummy=True)
        ipv6 = scan.make_event("2001:4860:4860::8888", dummy=True)
        netv6 = scan.make_event("2001:4860:4860::8888/126", dummy=True)
        domain = scan.make_event("publicAPIs.org", dummy=True)
        subdomain = scan.make_event("api.publicAPIs.org", dummy=True)
        open_port = scan.make_event("api.publicAPIs.org:443", dummy=True)
        ipv4_open_port = scan.make_event("8.8.8.8:443", dummy=True)
        ipv6_open_port = scan.make_event("[2001:4860:4860::8888]:443", "OPEN_TCP_PORT", dummy=True)
        url = scan.make_event("https://api.publicAPIs.org:443/hellofriend", dummy=True)
        ipv4_url = scan.make_event("https://8.8.8.8:443/hellofriend", dummy=True)
        ipv6_url = scan.make_event("https://[2001:4860:4860::8888]:443/hellofriend", "URL", dummy=True)
        url_hint = scan.make_event("https://api.publicAPIs.org:443/hello.ash", "URL_HINT", dummy=True)
        emoji = scan.make_event("💩", "WHERE_IS_YOUR_GOD_NOW", dummy=True)

    bbot_events.all = [  # noqa: F841
        bbot_events.ipv4,
        bbot_events.netv4,
        bbot_events.ipv6,
        bbot_events.netv6,
        bbot_events.domain,
        bbot_events.subdomain,
        bbot_events.open_port,
        bbot_events.ipv4_open_port,
        bbot_events.ipv6_open_port,
        bbot_events.url,
        bbot_events.url_hint,
        bbot_events.ipv4_url,
        bbot_events.ipv6_url,
        bbot_events.emoji,
    ]

    return bbot_events


@pytest.fixture
def patch_requests(monkeypatch):
    from bbot.core.helpers.web import request, download

    monkeypatch.setattr("urllib3.connectionpool.HTTPConnectionPool.urlopen", lambda *args, **kwargs: urllib_response)
    monkeypatch.setattr("urllib3.poolmanager.PoolManager.urlopen", lambda *args, **kwargs: urllib_response)
    monkeypatch.setattr("requests.adapters.HTTPAdapter.send", lambda *args, **kwargs: requests_response)
    monkeypatch.setattr("bbot.core.helpers.web.request", lambda *args, **kwargs: requests_response)
    Path("/tmp/nope").touch()
    monkeypatch.setattr("bbot.core.helpers.web.download", lambda *args, **kwargs: "/tmp/nope")
    return request, download


@pytest.fixture
def patch_commands(monkeypatch):
    import subprocess

    sample_output = [
        # httpx
        """{"timestamp":"2022-04-15T17:08:29.436778586-04:00","request":"GET /health HTTP/1.1\\r\\nHost: api.publicapis.org\\r\\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36\\r\\nAccept-Charset: utf-8\\r\\nAccept-Encoding: gzip\\r\\n\\r\\n","response-header":"HTTP/1.1 200 OK\\r\\nConnection: close\\r\\nContent-Length: 15\\r\\nContent-Type: text/plain; charset=utf-8\\r\\nDate: Fri, 15 Apr 2022 21:08:29 GMT\\r\\nServer: Caddy\\r\\nX-Rate-Limit-Duration: 1\\r\\nX-Rate-Limit-Limit: 10.00\\r\\nX-Rate-Limit-Request-Forwarded-For: 50.240.76.25\\r\\nX-Rate-Limit-Request-Remote-Addr: 172.17.0.1:32910\\r\\n\\r\\n","scheme":"https","port":"443","path":"/health","body-sha256":"6c63d4b385b07fe0e09a8a1f95b826e8a7d0401dfd12d649fe7c64b8a785023e","header-sha256":"161187846622dc97219392ab70195f4a477457e55dadf4b39f1b6c734e396120","url":"https://api.publicapis.org:443/health","input":"https://api.publicapis.org/health","webserver":"Caddy","response-body":"{\\"alive\\": true}","content-type":"text/plain","method":"GET","host":"138.197.231.124","content-length":15,"status-code":200,"response-time":"412.587433ms","failed":false,"lines":1,"words":2}""",
        # nuclei
        """{"template":"technologies/tech-detect.yaml","template-url":"https://github.com/projectdiscovery/nuclei-templates/blob/master/technologies/tech-detect.yaml","template-id":"tech-detect","info":{"name":"Wappalyzer Technology Detection","author":["hakluke"],"tags":["tech"],"reference":null,"severity":"info"},"matcher-name":"caddy","type":"http","host":"https://api.publicapis.org/health","matched-at":"https://api.publicapis.org:443/health","ip":"138.197.231.124","timestamp":"2022-04-15T17:09:01.021589723-04:00","curl-command":"curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2226.0 Safari/537.36' 'https://api.publicapis.org/health'","matcher-status":true,"matched-line":null}""",
        # dnsx
        """{"host":"api.publicapis.org","resolver":["1.0.0.1:53"],"a":["138.197.231.124"],"has_internal_ips":false,"status_code":"NOERROR","timestamp":"2022-04-15T17:11:24.746370988-04:00"}""",
        # url
        "https://api.publicapis.org:443/health",
        # open port
        "api.publicapis.org:443",
        # host
        "api.publicapis.org",
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

    from bbot import agent
    from bbot.modules.output.websocket import Websocket

    monkeypatch.setattr(Websocket, "send", lambda *args, **kwargs: True)

    test_agent = agent.Agent({"agent_url": "test", "agent_token": "test"})
    test_agent.setup()
    monkeypatch.setattr(test_agent, "ws", WebSocketApp())
    return test_agent
