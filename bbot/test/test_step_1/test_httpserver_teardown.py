"""Verify HTTP-server fixture teardown reports errors instead of clearing them."""

import pytest

from ..conftest import check_httpserver_errors


def test_httpserver_teardown_reports_assertions(bbot_httpserver):
    bbot_httpserver.add_assertion("fixture assertion was lost")
    with pytest.raises(AssertionError, match="fixture assertion was lost"):
        check_httpserver_errors(bbot_httpserver)
    assert bbot_httpserver.assertions == []


def test_httpserver_teardown_reports_handler_errors(bbot_httpserver):
    bbot_httpserver.handler_errors.append(ValueError("handler failure was lost"))
    with pytest.raises(ValueError, match="handler failure was lost"):
        check_httpserver_errors(bbot_httpserver)
    assert bbot_httpserver.handler_errors == []


def test_httpserver_teardown_allows_clean_server(bbot_httpserver):
    check_httpserver_errors(bbot_httpserver)
