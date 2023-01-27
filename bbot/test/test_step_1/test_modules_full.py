import logging

from ..bbot_fixtures import *  # noqa: F401
from ..modules_test_classes import *

log = logging.getLogger(f"bbot.test")


def test_gowitness(bbot_config, bbot_scanner, bbot_httpserver):
    x = Gowitness(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_otx(bbot_config, bbot_scanner, bbot_httpserver):
    x = Otx(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_anubisdb(bbot_config, bbot_scanner, bbot_httpserver):
    x = Anubisdb(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_httpx(bbot_config, bbot_scanner, bbot_httpserver):
    x = Httpx(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_getparam_brute(bbot_config, bbot_scanner, bbot_httpserver):
    x = Getparam_brute(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_telerik(bbot_config, bbot_scanner, bbot_httpserver):
    x = Telerik(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_leakix(bbot_config, bbot_scanner, bbot_httpserver):
    x = LeakIX(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_massdns(bbot_config, bbot_scanner, bbot_httpserver):
    x = Massdns(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_masscan(bbot_config, bbot_scanner, bbot_httpserver):
    x = Masscan(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_badsecrets(bbot_config, bbot_scanner, bbot_httpserver):
    x = Badsecrets(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()
