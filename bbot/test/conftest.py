import shutil
import pytest
import logging
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
    return ["127.0.0.1"] + interactsh_servers


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
