import ssl
import shutil
import pytest
import logging
from pathlib import Path
from pytest_httpserver import HTTPServer

from bbot.core.helpers.interactsh import server_list as interactsh_servers


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_sessionfinish(session, exitstatus):
    # Remove handlers from all loggers to prevent logging errors at exit
    loggers = [logging.getLogger("bbot")] + list(logging.Logger.manager.loggerDict.values())
    for logger in loggers:
        handlers = getattr(logger, "handlers", [])
        for handler in handlers:
            logger.removeHandler(handler)

    # Wipe out BBOT home dir
    shutil.rmtree("/tmp/.bbot_test", ignore_errors=True)

    yield


@pytest.fixture
def non_mocked_hosts() -> list:
    return ["127.0.0.1", "localhost"] + interactsh_servers


@pytest.fixture
def assert_all_responses_were_requested() -> bool:
    return False


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


@pytest.fixture
def bbot_httpserver_ssl():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    current_dir = Path(__file__).parent
    keyfile = str(current_dir / "testsslkey.pem")
    certfile = str(current_dir / "testsslcert.pem")
    context.load_cert_chain(certfile, keyfile)
    server = HTTPServer(host="127.0.0.1", port=9999, ssl_context=context)
    server.start()

    yield server

    server.clear()
    if server.is_running():
        server.stop()

    # this is to check if the client has made any request where no
    # `assert_request` was called on it from the test

    server.check_assertions()
    server.clear()


@pytest.fixture
def interactsh_mock_instance():
    interactsh_mock = Interactsh_mock()
    return interactsh_mock


class Interactsh_mock:
    def __init__(self):
        self.interactions = []
        self.correlation_id = "deadbeef-dead-beef-dead-beefdeadbeef"

    def mock_interaction(self, subdomain_tag):
        self.interactions.append(subdomain_tag)

    async def register(self, callback=None):
        return "fakedomain.fakeinteractsh.com"

    async def deregister(self, callback=None):
        pass

    async def poll(self):
        poll_results = []
        for subdomain_tag in self.interactions:
            poll_results.append({"full-id": f"{subdomain_tag}.fakedomain.fakeinteractsh.com", "protocol": "HTTP"})
        return poll_results


import threading
import http.server
import socketserver
import urllib.request


class Proxy(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "Proxy"
    urls = []

    def do_GET(self):
        self.urls.append(self.path)

        # Extract host and port from path
        netloc = urllib.parse.urlparse(self.path).netloc
        host, _, port = netloc.partition(":")

        # Fetch the content
        conn = http.client.HTTPConnection(host, port if port else 80)
        conn.request("GET", self.path, headers=self.headers)
        response = conn.getresponse()

        # Send the response back to the client
        self.send_response(response.status)
        for header, value in response.getheaders():
            self.send_header(header, value)
        self.end_headers()
        self.copyfile(response, self.wfile)

        response.close()
        conn.close()


@pytest.fixture
def proxy_server():
    # Set up an HTTP server that acts as a simple proxy.
    server = socketserver.ThreadingTCPServer(("localhost", 0), Proxy)

    # Start the server in a new thread.
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.start()

    yield server

    # Stop the server.
    server.shutdown()
    server_thread.join()
