"""The httpserver fixtures' teardown must report assertions and handler errors, not clear them first."""

import urllib.error
import urllib.request

import pytest

from ..conftest import FastShutdownHTTPServer, serve_and_check


@pytest.fixture
def server_teardown():
    """A server of its own, and the teardown the httpserver fixtures `yield from`, paused at its yield."""
    server = FastShutdownHTTPServer(host="127.0.0.1", port=0, threaded=True)
    server.start()
    teardown = serve_and_check(server)
    assert next(teardown) is server
    yield server, teardown
    if server.is_running():
        server.stop()


def get_status(server, path):
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(server.url_for(path), timeout=10)
    return e.value.code


def test_httpserver_teardown_reports_handler_errors(server_teardown):
    server, teardown = server_teardown

    def handler(request):
        raise ValueError("handler failure was lost")

    server.expect_request("/fail").respond_with_handler(handler)
    assert get_status(server, "/fail") == 500
    with pytest.raises(ValueError, match="handler failure was lost"):
        next(teardown)
    assert not server.is_running()
    assert server.handler_errors == []


def test_httpserver_teardown_reports_assertions(server_teardown):
    server, teardown = server_teardown

    def handler(request):
        raise AssertionError("fixture assertion was lost")

    server.expect_request("/assert").respond_with_handler(handler)
    assert get_status(server, "/assert") == 500
    with pytest.raises(AssertionError, match="fixture assertion was lost"):
        next(teardown)
    assert server.assertions == []


def test_httpserver_teardown_allows_clean_server(server_teardown):
    server, teardown = server_teardown
    # requests no handler matches are normal in brute-force tests and must not fail the test
    assert get_status(server, "/miss") == server.no_handler_status_code
    with pytest.raises(StopIteration):
        next(teardown)
    assert not server.is_running()
