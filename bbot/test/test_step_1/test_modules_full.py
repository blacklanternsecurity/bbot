import logging

from ..bbot_fixtures import *  # noqa: F401
from ..modules_test_classes import *

log = logging.getLogger(f"bbot.test")


def test_gowitness(bbot_config, bbot_scanner, bbot_httpserver):
    x = Gowitness(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_httpx(bbot_config, bbot_scanner, bbot_httpserver):
    x = Httpx(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_excavate(bbot_config, bbot_scanner, bbot_httpserver):
    x = Excavate(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_subdomain_hijack(bbot_config, bbot_scanner, bbot_httpserver):
    x = Subdomain_Hijack(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_fingerprintx(bbot_config, bbot_scanner, bbot_httpserver):
    x = Fingerprintx(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_otx(bbot_config, bbot_scanner, bbot_httpserver):
    x = Otx(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_anubisdb(bbot_config, bbot_scanner, bbot_httpserver):
    x = Anubisdb(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_paramminer_getparams(bbot_config, bbot_scanner, bbot_httpserver):
    x = Paramminer_getparams(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_paramminer_headers(bbot_config, bbot_scanner, bbot_httpserver):
    x = Paramminer_headers(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_paramminer_cookies(bbot_config, bbot_scanner, bbot_httpserver):
    x = Paramminer_cookies(bbot_config, bbot_scanner, bbot_httpserver)
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


def test_secretsdb(bbot_config, bbot_scanner, bbot_httpserver):
    x = SecretsDB(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_badsecrets(bbot_config, bbot_scanner, bbot_httpserver):
    x = Badsecrets(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_robots(bbot_config, bbot_scanner, bbot_httpserver):
    x = Robots(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_buckets(bbot_config, bbot_scanner, bbot_httpserver):
    x = Buckets(bbot_config, bbot_scanner, bbot_httpserver, module_name="excavate")
    x.run()


def test_asn(bbot_config, bbot_scanner, bbot_httpserver):
    x = ASN(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_wafw00f(bbot_config, bbot_scanner, bbot_httpserver):
    x = Wafw00f(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_ffuf(bbot_config, bbot_scanner, bbot_httpserver):
    x = Ffuf(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_ffuf_extensions(bbot_config, bbot_scanner, bbot_httpserver):
    x = Ffuf_extensions(bbot_config, bbot_scanner, bbot_httpserver, module_name="ffuf")
    x.run()


def test_bypass403(bbot_config, bbot_scanner, bbot_httpserver):
    x = Bypass403(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_bypass403_waf(bbot_config, bbot_scanner, bbot_httpserver):
    x = Bypass403_waf(bbot_config, bbot_scanner, bbot_httpserver, module_name="bypass403")
    x.run()


def test_bypass403_aspnetcookieless(bbot_config, bbot_scanner, bbot_httpserver):
    x = Bypass403_aspnetcookieless(bbot_config, bbot_scanner, bbot_httpserver, module_name="bypass403")
    x.run()


def test_ffuf_shortnames(bbot_config, bbot_scanner, bbot_httpserver):
    x = Ffuf_shortnames(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_iis_shortnames(bbot_config, bbot_scanner, bbot_httpserver):
    x = Iis_shortnames(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_nuclei_technology(bbot_config, bbot_scanner, bbot_httpserver, caplog):
    x = Nuclei_technology(bbot_config, bbot_scanner, bbot_httpserver, caplog, module_name="nuclei")
    x.run()


def test_nuclei_manual(bbot_config, bbot_scanner, bbot_httpserver):
    x = Nuclei_manual(bbot_config, bbot_scanner, bbot_httpserver, module_name="nuclei")
    x.run()


def test_nuclei_severe(bbot_config, bbot_scanner, bbot_httpserver):
    x = Nuclei_severe(bbot_config, bbot_scanner, bbot_httpserver, module_name="nuclei")
    x.run()


def test_nuclei_budget(bbot_config, bbot_scanner, bbot_httpserver):
    x = Nuclei_budget(bbot_config, bbot_scanner, bbot_httpserver, module_name="nuclei")
    x.run()


def test_url_manipulation(bbot_config, bbot_scanner, bbot_httpserver):
    x = Url_manipulation(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_naabu(bbot_config, bbot_scanner, bbot_httpserver):
    x = Naabu(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_hunt(bbot_config, bbot_scanner, bbot_httpserver):
    x = Hunt(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_vhost(bbot_config, bbot_scanner, bbot_httpserver):
    x = Vhost(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()


def test_speculate_subdirectories(bbot_config, bbot_scanner, bbot_httpserver):
    x = Speculate_subdirectories(bbot_config, bbot_scanner, bbot_httpserver, module_name="speculate")
    x.run()


def test_social(bbot_config, bbot_scanner, bbot_httpserver):
    x = Social(bbot_config, bbot_scanner, bbot_httpserver)
    x.run()
