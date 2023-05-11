import logging

from ..bbot_fixtures import *  # noqa: F401
from ..modules_test_classes import *

log = logging.getLogger(f"bbot.test")


@pytest.mark.asyncio
async def test_httpx(request):
    x = Httpx(request)
    await x.run()


@pytest.mark.asyncio
async def test_gowitness(request):
    x = Gowitness(request)
    await x.run()


@pytest.mark.asyncio
async def test_excavate(request):
    x = Excavate(request)
    await x.run()


@pytest.mark.asyncio
async def test_excavate_relativelinks(request):
    x = Excavate_relativelinks(request, module_name="excavate")
    await x.run()


@pytest.mark.asyncio
async def test_subdomain_hijack(request):
    x = Subdomain_Hijack(request)
    await x.run()


@pytest.mark.asyncio
async def test_fingerprintx(request):
    x = Fingerprintx(request)
    await x.run()


@pytest.mark.asyncio
async def test_otx(request):
    x = Otx(request)
    await x.run()


@pytest.mark.asyncio
async def test_anubisdb(request):
    x = Anubisdb(request)
    await x.run()


@pytest.mark.asyncio
async def test_secretsdb(request):
    x = SecretsDB(request)
    await x.run()


@pytest.mark.asyncio
async def test_badsecrets(request):
    x = Badsecrets(request)
    await x.run()


@pytest.mark.asyncio
async def test_telerik(request):
    x = Telerik(request)
    await x.run()


@pytest.mark.asyncio
async def test_paramminer_headers(request):
    x = Paramminer_headers(request)
    await x.run()


@pytest.mark.asyncio
async def test_paramminer_getparams(request):
    x = Paramminer_getparams(request)
    await x.run()


@pytest.mark.asyncio
async def test_paramminer_cookies(request):
    x = Paramminer_cookies(request)
    await x.run()


@pytest.mark.asyncio
async def test_leakix(request):
    x = LeakIX(request)
    await x.run()


@pytest.mark.asyncio
async def test_massdns(request):
    x = Massdns(request)
    await x.run()


@pytest.mark.asyncio
async def test_masscan(request):
    x = Masscan(request)
    await x.run()


@pytest.mark.asyncio
async def test_robots(request):
    x = Robots(request)
    await x.run()


@pytest.mark.asyncio
async def test_buckets(request):
    x = Buckets(request, module_name="excavate")
    await x.run()


@pytest.mark.asyncio
async def test_asn(request):
    x = ASN(request)
    await x.run()


@pytest.mark.asyncio
async def test_wafw00f(request):
    x = Wafw00f(request)
    await x.run()


@pytest.mark.asyncio
async def test_ffuf(request):
    x = Ffuf(request)
    await x.run()


@pytest.mark.asyncio
async def test_ffuf_extensions(request):
    x = Ffuf_extensions(request, module_name="ffuf")
    await x.run()


@pytest.mark.asyncio
async def test_bypass403(request):
    x = Bypass403(request)
    await x.run()


@pytest.mark.asyncio
async def test_bypass403_waf(request):
    x = Bypass403_waf(request, module_name="bypass403")
    await x.run()


@pytest.mark.asyncio
async def test_bypass403_aspnetcookieless(request):
    x = Bypass403_aspnetcookieless(request, module_name="bypass403")
    await x.run()


@pytest.mark.asyncio
async def test_ffuf_shortnames(request):
    x = Ffuf_shortnames(request)
    await x.run()


@pytest.mark.asyncio
async def test_iis_shortnames(request):
    x = Iis_shortnames(request)
    await x.run()


@pytest.mark.asyncio
async def test_nuclei_technology(request, caplog):
    x = Nuclei_technology(request, caplog, module_name="nuclei")
    await x.run()


@pytest.mark.asyncio
async def test_nuclei_manual(request):
    x = Nuclei_manual(request, module_name="nuclei")
    await x.run()


@pytest.mark.asyncio
async def test_nuclei_severe(request):
    x = Nuclei_severe(request, module_name="nuclei")
    await x.run()


@pytest.mark.asyncio
async def test_nuclei_budget(request):
    x = Nuclei_budget(request, module_name="nuclei")
    await x.run()


@pytest.mark.asyncio
async def test_url_manipulation(request):
    x = Url_manipulation(request)
    await x.run()


@pytest.mark.asyncio
async def test_naabu(request):
    x = Naabu(request)
    await x.run()


@pytest.mark.asyncio
async def test_hunt(request):
    x = Hunt(request)
    await x.run()


@pytest.mark.asyncio
async def test_vhost(request):
    x = Vhost(request)
    await x.run()


@pytest.mark.asyncio
async def test_speculate_subdirectories(request):
    x = Speculate_subdirectories(request, module_name="speculate")
    await x.run()


@pytest.mark.asyncio
async def test_social(request):
    x = Social(request)
    await x.run()
