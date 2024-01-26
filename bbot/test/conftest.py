import ssl
import shutil
import pytest
import asyncio
import logging
from pathlib import Path
from pytest_httpserver import HTTPServer

from bbot.core.helpers.misc import execute_sync_or_async
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
    return ["127.0.0.1", "localhost", "raw.githubusercontent.com"] + interactsh_servers


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
def bbot_httpserver_allinterfaces():
    server = HTTPServer(host="0.0.0.0", port=5556)
    server.start()

    yield server

    server.clear()
    if server.is_running():
        server.stop()
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
        self.stop = False

    def mock_interaction(self, subdomain_tag):
        self.interactions.append(subdomain_tag)

    async def register(self, callback=None):
        if callable(callback):
            asyncio.create_task(self.poll_loop(callback))
        return "fakedomain.fakeinteractsh.com"

    async def deregister(self, callback=None):
        self.stop = True

    async def poll_loop(self, callback=None):
        while not self.stop:
            data_list = await self.poll(callback)
            if not data_list:
                await asyncio.sleep(1)
                continue

    async def poll(self, callback=None):
        poll_results = []
        for subdomain_tag in self.interactions:
            result = {"full-id": f"{subdomain_tag}.fakedomain.fakeinteractsh.com", "protocol": "HTTP"}
            poll_results.append(result)
            if callback is not None:
                await execute_sync_or_async(callback, result)
        self.interactions = []
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


class MockResolver:
    import dns

    def __init__(self, mock_data=None):
        self.mock_data = mock_data if mock_data else {}
        self.nameservers = ["127.0.0.1"]

    async def resolve_address(self, host):
        try:
            from dns.asyncresolver import resolve_address

            result = await resolve_address(host)
            return result
        except ImportError:
            raise ImportError("dns.asyncresolver.Resolver.resolve_address not found")

    def create_dns_response(self, query_name, rdtype):
        answers = self.mock_data.get(query_name, {}).get(rdtype, [])
        if not answers:
            raise self.dns.resolver.NXDOMAIN(f"No answer found for {query_name} {rdtype}")

        message_text = f"""id 1234
opcode QUERY
rcode NOERROR
flags QR AA RD
;QUESTION
{query_name}. IN {rdtype}
;ANSWER"""
        for answer in answers:
            message_text += f"\n{query_name}. 1 IN {rdtype} {answer}"

        message_text += "\n;AUTHORITY\n;ADDITIONAL\n"
        message = self.dns.message.from_text(message_text)
        return message

    async def resolve(self, query_name, rdtype=None):
        if rdtype is None:
            rdtype = "A"
        elif isinstance(rdtype, str):
            rdtype = rdtype.upper()
        else:
            rdtype = str(rdtype.name).upper()

        domain_name = self.dns.name.from_text(query_name)
        rdtype_obj = self.dns.rdatatype.from_text(rdtype)


        if "_NXDOMAIN" in self.mock_data and query_name in self.mock_data["_NXDOMAIN"]:
            # Simulate the NXDOMAIN exception
            raise self.dns.resolver.NXDOMAIN

        try:
            response = self.create_dns_response(query_name, rdtype)
            answer = self.dns.resolver.Answer(domain_name, rdtype_obj, self.dns.rdataclass.IN, response)
            return answer
        except self.dns.resolver.NXDOMAIN as e:
            return []


@pytest.fixture()
def configure_mock_resolver(monkeypatch):
    def _configure(mock_data):
        mock_resolver = MockResolver(mock_data)
        return mock_resolver
    return _configure
