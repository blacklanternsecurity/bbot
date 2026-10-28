import os
import re
import ssl
import json
import time
import asyncio
import platform
import threading
import datetime

import psutil
from werkzeug.wrappers import Response

from ..bbot_fixtures import *
from bbot.errors import BrowserError
from bbot.core.helpers.web.browser.engines import camoufox
from pytest_httpserver import HTTPServer
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# tests marked `browser` drive a real browser, installed by the deps installer when web.enable_browser is on.
# they only run when BBOT_TEST_BROWSER is set (see conftest.py)

JS_PAGE = """<html><head><title>js page</title></head><body>
<h1 id="x">static</h1>
<img src="/pixel.png">
<img src="http://localhost:8888/blocked.png">
<script>document.getElementById("x").textContent = "built by js"</script>
</body></html>"""

# shaped like a Cloudflare managed challenge: blasthttp concludes needs_browser, and the page's script clears it
CHALLENGE_PAGE = """<html><head><title>Just a moment...</title></head><body><script>
document.cookie = "cleared=1; path=/";
setTimeout(() => location.reload(), 200);
</script></body></html>"""
CHALLENGE_HEADERS = {"Server": "cloudflare", "cf-mitigated": "challenge"}


def serve(httpserver):
    """A site with a JavaScript-built page, a challenge that clears itself, and a binary file."""

    def handler(request):
        if request.path.startswith("/challenge") and request.cookies.get("cleared") != "1":
            return Response(
                CHALLENGE_PAGE,
                status=403,
                headers=CHALLENGE_HEADERS,
                content_type="text/html",
            )
        if request.path.startswith("/challenge"):
            return Response(
                "<html><head><title>real</title></head>past the challenge</html>", content_type="text/html"
            )
        if request.path == "/binary":
            return Response(bytes(range(256)), content_type="application/octet-stream")
        if request.path.endswith(".png") or request.path == "/favicon.ico":
            return Response(b"", status=404)
        return Response(JS_PAGE, content_type="text/html")

    httpserver.expect_request(re.compile(".*")).respond_with_handler(handler)


def requested_paths(httpserver):
    return [request.path for request, _ in httpserver.log]


def browser_processes():
    return [p for p in psutil.Process(os.getpid()).children(recursive=True) if "camoufox" in p.name()]


async def no_browser_processes():
    """Whether every browser process exits; closing one takes a moment."""
    for _ in range(100):
        if not browser_processes():
            return True
        await asyncio.sleep(0.1)
    return False


async def browser_scan(bbot_scanner, **web_config):
    # screenshot and browser_dom want different things from the same page load
    scan = bbot_scanner(
        "127.0.0.1",
        modules=["screenshot", "browser_dom"],
        blacklist=["localhost"],
        config={"web": {"enable_browser": True, **web_config}},
    )
    await scan._prep()
    return scan


@pytest.mark.asyncio
async def test_browser_disabled(bbot_scanner):
    scan = bbot_scanner("127.0.0.1")
    await scan._prep()
    browser = scan.helpers.browser
    assert browser.enabled is False
    with pytest.raises(BrowserError, match="web.enable_browser"):
        await browser.visit("http://127.0.0.1:8888/")
    with pytest.raises(BrowserError, match="web.enable_browser"):
        await browser.fetch("http://127.0.0.1:8888/")
    await scan._cleanup()


@pytest.mark.browser
@pytest.mark.asyncio
async def test_browser_visit(bbot_scanner, bbot_httpserver):
    serve(bbot_httpserver)
    scan = await browser_scan(bbot_scanner, http_headers={"X-Bbot-Test": "bbot-test-value"})
    browser = scan.helpers.browser
    url = bbot_httpserver.url_for("/")

    # both modules ask at once: the page is loaded once and both get the same visit
    shots, dom = await asyncio.gather(
        browser.visit(url, consumer="screenshot"), browser.visit(url, consumer="browser_dom")
    )
    assert shots is dom
    assert requested_paths(bbot_httpserver).count("/") == 1
    # once every interested module has collected it, it's no longer held
    assert url not in browser._visits

    visit = shots
    assert visit.response.status_code == 200
    assert visit.response.conclusion == ("reached", "-")
    assert visit.title == "js page"
    # the DOM after scripts ran, not the HTML as served
    assert "built by js" in visit.dom
    assert visit.screenshot.startswith(b"\x89PNG")
    network = {n["url"]: n for n in visit.network}
    pixel = network[bbot_httpserver.url_for("/pixel.png")]
    assert pixel["resource_type"] == "image"
    # only text resources keep their response
    assert pixel["response"] is None

    # blacklisted hosts are never contacted, even for a page's subresources
    assert "/blocked.png" not in requested_paths(bbot_httpserver)
    # custom headers go on in-scope requests, as with blasthttp
    first_request = next(request for request, _ in bbot_httpserver.log if request.path == "/")
    assert first_request.headers.get("X-Bbot-Test") == "bbot-test-value"

    await scan._cleanup()
    assert await no_browser_processes()


@pytest.mark.browser
@pytest.mark.asyncio
async def test_browser_challenge_and_fetch(bbot_scanner, bbot_httpserver):
    serve(bbot_httpserver)
    scan = await browser_scan(bbot_scanner)
    browser = scan.helpers.browser

    # blasthttp can't get past the challenge
    response = await scan.helpers.request(bbot_httpserver.url_for("/challenge"))
    assert response.conclusion == ("needs_browser", "cloudflare")

    # the browser waits it out and lands on the real page
    visit = await browser.visit(bbot_httpserver.url_for("/challenge"))
    assert visit.response.status_code == 200
    assert visit.response.conclusion == ("reached", "-")
    assert "past the challenge" in visit.response.text

    # a fetch on the same origin carries the cookie the challenge set
    response = await browser.fetch(bbot_httpserver.url_for("/challenge/data"))
    assert response.status_code == 200
    assert "past the challenge" in response.text

    # fetch returns bodies byte for byte
    response = await browser.fetch(bbot_httpserver.url_for("/binary"))
    assert response.status_code == 200
    assert response.content == bytes(range(256))
    assert response.headers["content-type"] == "application/octet-stream"

    await scan._cleanup()


# pages that send themselves elsewhere, each after building some content with a script
BUILD_JS = 'document.body.insertAdjacentHTML("beforeend", "<p>built before leaving</p>");'
REDIRECT_PAGES = {
    "/inline": f"<script>{BUILD_JS} location.href = '/dest';</script>",
    "/replace": f"<script>{BUILD_JS} location.replace('/dest');</script>",
    "/onload": f"<script>window.onload = () => {{ {BUILD_JS} location.href = '/dest'; }};</script>",
    "/timeout": f"<script>{BUILD_JS} setTimeout(() => location.href = '/dest', 300);</script>",
    "/meta": f'<meta http-equiv="refresh" content="0;url=/dest"><script>{BUILD_JS}</script>',
    "/form": f'<form id="f" action="/dest" method="POST"></form><script>{BUILD_JS} document.getElementById("f").submit();</script>',
    # long after the page has settled and been captured
    "/late": f"<script>{BUILD_JS} setTimeout(() => location.href = '/dest', 8000);</script>",
}


@pytest.mark.browser
@pytest.mark.asyncio
async def test_browser_redirect_hold(bbot_scanner, bbot_httpserver):
    def handler(request):
        if request.path == "/http-redirect":
            return Response("", status=302, headers={"Location": "/landing"})
        body = REDIRECT_PAGES.get(request.path, "destination")
        return Response(f"<html><body>{body}</body></html>", content_type="text/html")

    bbot_httpserver.expect_request(re.compile(".*")).respond_with_handler(handler)
    scan = await browser_scan(bbot_scanner)
    browser = scan.helpers.browser
    dest = bbot_httpserver.url_for("/dest")

    for path in ("/inline", "/replace", "/onload", "/timeout", "/meta", "/form"):
        url = bbot_httpserver.url_for(path)
        start = time.monotonic()
        visit = await browser.visit(url)
        # a redirect before the page finishes loading doesn't leave us waiting for a load that never comes
        assert time.monotonic() - start < 20, path
        # the page we asked for, as its script left it
        assert visit.response.url == url, path
        assert "built before leaving" in visit.dom, path
        assert visit.redirect == ("POST" if path == "/form" else "GET", dest), path

    late = await browser.visit(bbot_httpserver.url_for("/late"))
    assert late.redirect is None
    assert "built before leaving" in late.dom

    # the server's own redirect isn't held: the browser follows it like any client
    followed = await browser.visit(bbot_httpserver.url_for("/http-redirect"))
    assert followed.response.url == bbot_httpserver.url_for("/landing")
    assert followed.redirect is None

    # the browser never went to the destination
    assert "/dest" not in requested_paths(bbot_httpserver)
    await scan._cleanup()


@pytest.mark.browser
@pytest.mark.asyncio
async def test_browser_redirect_to_nowhere(bbot_scanner, bbot_httpserver):
    """A redirect to somewhere that doesn't answer is a failed load, not a visit to the browser's own error page."""
    bbot_httpserver.expect_request("/").respond_with_data("", status=302, headers={"Location": "http://127.0.0.1:1/"})
    scan = await browser_scan(bbot_scanner)
    assert await scan.helpers.browser.visit(bbot_httpserver.url_for("/")) is None
    await scan._cleanup()


@pytest.mark.browser
@pytest.mark.asyncio
async def test_browser_stalled_font(bbot_scanner, bbot_httpserver, monkeypatch):
    """A web font that never finishes loading doesn't cost the page its screenshot."""
    monkeypatch.setattr("bbot.core.helpers.web.browser.helper.FONT_TIMEOUT", 3)
    # the font is only requested after the load event, so the page loads but its fonts never settle
    page = """<html><head><style>@font-face { font-family: stalled; src: url(/font.woff2); }</style></head><body>
<script>addEventListener("load", () => { const p = document.createElement("p"); p.style.fontFamily = "stalled"; p.textContent = "late"; document.body.append(p); })</script>
</body></html>"""
    font_requested, release = threading.Event(), threading.Event()

    def handler(request):
        if request.path == "/font.woff2":
            font_requested.set()
            release.wait(60)
            return Response(b"", content_type="font/woff2")
        return Response(page, content_type="text/html")

    bbot_httpserver.expect_request(re.compile(".*")).respond_with_handler(handler)
    scan = await browser_scan(bbot_scanner)
    try:
        visit = await scan.helpers.browser.visit(bbot_httpserver.url_for("/"))
        assert font_requested.is_set()
        assert visit.screenshot.startswith(b"\x89PNG")
    finally:
        release.set()
        await scan._cleanup()


@pytest.mark.browser
@pytest.mark.asyncio
async def test_browser_crash_recovery(bbot_scanner, bbot_httpserver):
    serve(bbot_httpserver)
    scan = await browser_scan(bbot_scanner)
    browser = scan.helpers.browser
    url = bbot_httpserver.url_for("/")

    async def crash():
        for process in browser_processes():
            process.kill()
        # wait for the disconnect to be noticed
        for _ in range(50):
            if browser._instance is None:
                return
            await asyncio.sleep(0.1)

    assert await browser.visit(url) is not None

    # a crashed browser is relaunched for the next page
    await crash()
    assert len(browser._crashes) == 1
    visit = await browser.visit(bbot_httpserver.url_for("/again"))
    assert visit is not None and visit.response.status_code == 200
    assert browser.usable

    # one that keeps crashing is given up on for the rest of the scan
    await crash()
    assert await browser.visit(bbot_httpserver.url_for("/third")) is not None
    await crash()
    assert len(browser._crashes) == 3
    assert not browser.usable
    assert await browser.visit(bbot_httpserver.url_for("/fourth")) is None

    await scan._cleanup()
    assert await no_browser_processes()


@pytest.mark.browser
@pytest.mark.asyncio
async def test_browser_recycle_and_idle(bbot_scanner, bbot_httpserver):
    serve(bbot_httpserver)
    scan = await browser_scan(bbot_scanner, browser_recycle_after=2, browser_idle_timeout=1)
    browser = scan.helpers.browser

    # restarted after browser_recycle_after pages
    await browser.visit(bbot_httpserver.url_for("/1"))
    first = browser._instance
    await browser.visit(bbot_httpserver.url_for("/2"))
    assert browser._instance is first
    await browser.visit(bbot_httpserver.url_for("/3"))
    assert browser._instance is not first
    assert not first.alive
    # a restart isn't a crash
    assert not browser._crashes

    # shut down after browser_idle_timeout seconds unused, and relaunched when needed
    for _ in range(50):
        if browser._instance is None:
            break
        await asyncio.sleep(0.1)
    assert browser._instance is None
    assert await no_browser_processes()
    assert await browser.visit(bbot_httpserver.url_for("/4")) is not None

    await scan._cleanup()
    assert await no_browser_processes()


@pytest.mark.browser
@pytest.mark.asyncio
async def test_browser_host_eviction(bbot_scanner):
    """Contexts beyond browser_max_pages are closed oldest first, but never one in use or the one just opened."""
    scan = await browser_scan(bbot_scanner, browser_max_pages=1)
    browser = scan.helpers.browser

    instance, busy = await browser._host("http://127.0.0.1:8001/")
    busy.active += 1
    # the busy origin survives a new one arriving, and the new one isn't evicted to make room
    instance, new = await browser._host("http://127.0.0.1:8002/")
    assert set(instance.hosts) == {"http://127.0.0.1:8001", "http://127.0.0.1:8002"}

    # once idle, older origins make way
    busy.active -= 1
    instance, newest = await browser._host("http://127.0.0.1:8003/")
    assert set(instance.hosts) == {"http://127.0.0.1:8003"}

    await scan._cleanup()
    assert await no_browser_processes()


@pytest.mark.browser
@pytest.mark.asyncio
async def test_browser_one_context_per_origin(bbot_scanner):
    """A URL with its scheme's default port and one without are the same origin, and share a context and its cookies."""
    scan = await browser_scan(bbot_scanner)
    browser = scan.helpers.browser

    _, https = await browser._host("https://127.0.0.1:443/login")
    _, https_bare = await browser._host("https://127.0.0.1/")
    _, http = await browser._host("http://127.0.0.1:80/")
    _, http_bare = await browser._host("http://127.0.0.1/robots.txt")
    instance, other_port = await browser._host("http://127.0.0.1:8001/")
    assert https is https_bare
    assert http is http_bare
    assert other_port is not http
    assert set(instance.hosts) == {"https://127.0.0.1", "http://127.0.0.1", "http://127.0.0.1:8001"}

    await scan._cleanup()
    assert await no_browser_processes()


def make_cert(name, issuer=None):
    """A certificate for `name` and its key, signed by `issuer` (a cert and key) or self-signed as a CA."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    issuer_cert, issuer_key = issuer or (None, key)
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    if issuer is None:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    else:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
    return builder.sign(issuer_key, hashes.SHA256()), key


@pytest.mark.browser
@pytest.mark.asyncio
@pytest.mark.skipif(platform.system() != "Linux", reason="mirrors the Linux browser install")
async def test_browser_ignores_hsts(bbot_scanner, bbot_httpserver, tmp_path, monkeypatch):
    """Once a host's https has sent Strict-Transport-Security, its http on another port still loads."""
    # Firefox only learns HSTS over a certificate it trusts, so the browser has to trust this one
    ca = make_cert("bbot test CA")
    cert, key = make_cert("hsts.test", issuer=ca)
    (tmp_path / "ca.pem").write_bytes(ca[0].public_bytes(serialization.Encoding.PEM))
    (tmp_path / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "key.pem").write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )

    scan = await browser_scan(bbot_scanner)
    # a copy of the installed browser with the CA added to its policies, linked rather than copied where it can be
    installed = scan.helpers.browser.engine.install_dir
    browser_dir = tmp_path / "browser"
    browser_dir.mkdir()
    for entry in installed.iterdir():
        if entry.name in ("camoufox", "camoufox-bin", "camoufox.cfg"):
            (browser_dir / entry.name).write_bytes(entry.read_bytes())
            (browser_dir / entry.name).chmod(entry.stat().st_mode)
        elif entry.name != "distribution":
            (browser_dir / entry.name).symlink_to(entry)
    policies = json.loads((installed / "distribution" / "policies.json").read_text())
    policies["policies"]["Certificates"] = {"Install": [str(tmp_path / "ca.pem")]}
    (browser_dir / "distribution").mkdir()
    (browser_dir / "distribution" / "policies.json").write_text(json.dumps(policies))
    monkeypatch.setattr(camoufox.CamoufoxEngine, "install_dir", property(lambda self: browser_dir))
    monkeypatch.setitem(camoufox.FIREFOX_PREFS, "network.dns.localDomains", "hsts.test")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(tmp_path / "cert.pem", tmp_path / "key.pem")
    https = HTTPServer(host="127.0.0.1", port=0, ssl_context=context)
    https.expect_request("/").respond_with_data(
        "<html><title>https</title></html>",
        content_type="text/html",
        headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"},
    )
    https.start()
    bbot_httpserver.expect_request("/").respond_with_data("<html><title>http</title></html>", content_type="text/html")

    try:
        browser = scan.helpers.browser
        secure = await browser.visit(f"https://hsts.test:{https.port}/")
        assert secure.title == "https"
        # the scan still sees the header
        assert secure.response.headers.get("strict-transport-security") == "max-age=31536000; includeSubDomains"
        plain = await browser.visit(f"http://hsts.test:{bbot_httpserver.port}/")
        assert plain is not None and plain.title == "http"
        assert plain.response.url == f"http://hsts.test:{bbot_httpserver.port}/"
        assert (browser_dir / "camoufox.cfg").read_text().count(camoufox.HSTS_HOOK_MARKER) == 1
    finally:
        await scan._cleanup()
        https.stop()


@pytest.mark.browser
@pytest.mark.asyncio
async def test_browser_fallback_handoff(bbot_scanner, bbot_httpserver):
    """The browser passes a challenge and hands its cookies and User-Agent to blasthttp, for every later request."""
    serve(bbot_httpserver)
    scan = await browser_scan(bbot_scanner)
    web = scan.helpers.web
    url = bbot_httpserver.url_for("/challenge")

    # not opted in: the challenge comes back as is, and the browser isn't involved
    response = await web.request(url)
    assert response.conclusion == ("needs_browser", "cloudflare")
    assert scan.helpers.browser._instance is None
    assert web.is_browser_only("127.0.0.1")

    # opted in: blasthttp gets through with the browser's cookies
    response = await web.request(url, browser_fallback=True)
    assert response.status_code == 200
    assert "past the challenge" in response.text
    clearance = web._clearances["127.0.0.1"]
    assert clearance.cookies == {"cleared": "1"}
    assert "Firefox" in clearance.user_agent
    assert not web.is_browser_only("127.0.0.1")

    # every later request to the host carries the clearance, opted in or not
    response = await web.request(bbot_httpserver.url_for("/challenge/later"))
    assert response.status_code == 200
    later_request = [request for request, _ in bbot_httpserver.log if request.path == "/challenge/later"][-1]
    assert later_request.cookies.get("cleared") == "1"
    assert later_request.headers.get("User-Agent") == clearance.user_agent
    # but a caller's own User-Agent wins
    await web.request(bbot_httpserver.url_for("/challenge/custom-ua"), headers={"User-Agent": "custom"})
    custom = [request for request, _ in bbot_httpserver.log if request.path == "/challenge/custom-ua"][-1]
    assert custom.headers.get("User-Agent") == "custom"
    assert custom.cookies.get("cleared") == "1"

    await scan._cleanup()


@pytest.mark.browser
@pytest.mark.asyncio
async def test_browser_fallback_off(bbot_scanner, bbot_httpserver):
    serve(bbot_httpserver)
    # the browser is on for screenshots and DOMs, but blasthttp doesn't hand challenges to it
    scan = await browser_scan(bbot_scanner, browser_fallback=False)
    browser = scan.helpers.browser

    response = await scan.helpers.request(bbot_httpserver.url_for("/challenge"), browser_fallback=True)
    assert response.conclusion == ("needs_browser", "cloudflare")
    assert browser._instance is None
    assert not scan.helpers.web._clearances

    # the browser modules still get their pages
    visit = await browser.visit(bbot_httpserver.url_for("/"))
    assert visit.response.status_code == 200
    await scan._cleanup()


@pytest.mark.browser
@pytest.mark.asyncio
async def test_browser_challenge_without_reload(bbot_scanner, bbot_httpserver, monkeypatch):
    """A challenge whose script sets its cookie but doesn't reload is passed by reloading it."""
    monkeypatch.setattr("bbot.core.helpers.web.browser.helper.CHALLENGE_RELOAD_AFTER", 1)
    browser_loads = []

    def handler(request):
        # blasthttp sends navigation headers on one rung, and borrows the browser's User-Agent after a handoff
        if "Firefox" in request.headers.get("User-Agent", "") and request.headers.get("Sec-Fetch-Mode") == "navigate":
            browser_loads.append(request.path)
        if request.cookies.get("cleared") == "1":
            return Response(
                "<html><head><title>real</title></head>past the challenge</html>", content_type="text/html"
            )
        page = '<html><head><title>Just a moment...</title></head><body><script>document.cookie = "cleared=1; path=/"</script></body></html>'
        return Response(page, status=403, headers=CHALLENGE_HEADERS, content_type="text/html")

    bbot_httpserver.expect_request(re.compile(".*")).respond_with_handler(handler)
    scan = await browser_scan(bbot_scanner)
    web = scan.helpers.web

    start = time.monotonic()
    response = await web.request(bbot_httpserver.url_for("/page"), browser_fallback=True)
    assert response.status_code == 200
    assert "past the challenge" in response.text
    assert web._clearances["127.0.0.1"].cookies == {"cleared": "1"}
    # the challenge load and the reload
    assert browser_loads == ["/page", "/page"]
    assert time.monotonic() - start < 15
    assert not web.is_browser_only("127.0.0.1")

    await scan._cleanup()


@pytest.mark.browser
@pytest.mark.asyncio
async def test_browser_unpassable_host(bbot_scanner, bbot_httpserver, monkeypatch):
    """A host whose challenge the browser can't pass either gets one browser load, and no more."""
    monkeypatch.setattr("bbot.core.helpers.web.browser.helper.CHALLENGE_TIMEOUT", 2)
    monkeypatch.setattr("bbot.core.helpers.web.browser.helper.CHALLENGE_RELOAD_AFTER", 1)
    browser_loads = []

    def handler(request):
        if "Firefox" in request.headers.get("User-Agent", "") and request.headers.get("Sec-Fetch-Mode") == "navigate":
            browser_loads.append(request.path)
        # the protection's own redirect, like http to https
        if request.path == "/redirect":
            return Response("", status=301, headers={"Location": "/first"})
        # a challenge that never clears, for blasthttp and the browser alike
        page = "<html><head><title>Just a moment...</title></head><body>still checking</body></html>"
        return Response(page, status=403, headers=CHALLENGE_HEADERS, content_type="text/html")

    bbot_httpserver.expect_request(re.compile(".*")).respond_with_handler(handler)
    scan = await browser_scan(bbot_scanner)
    web = scan.helpers.web

    # a redirect doesn't count as reaching the host
    response = await web.request(bbot_httpserver.url_for("/redirect"))
    assert response.status_code == 301
    assert not web.is_browser_only("127.0.0.1")

    # the clearance gets the same challenge, and the same again when it reloads, so there's no fetch after it
    response = await web.request(bbot_httpserver.url_for("/first"), browser_fallback=True)
    assert response.conclusion == ("needs_browser", "cloudflare")
    assert browser_loads == ["/first", "/first"]
    assert web.is_unpassable("127.0.0.1")
    assert web.is_browser_only("127.0.0.1")

    # later requests to the host don't go to the browser
    response = await web.request(bbot_httpserver.url_for("/second"), browser_fallback=True)
    assert response.conclusion == ("needs_browser", "cloudflare")
    assert browser_loads == ["/first", "/first"]

    # and neither do the browser modules
    page = scan.make_event(
        {"url": bbot_httpserver.url_for("/third"), "content_type": "text/html"},
        "URL",
        parent=scan.root_event,
        tags=["status-200"],
    )
    page.scope_distance = 0
    for module in ("screenshot", "browser_dom"):
        accepted, reason = await scan.modules[module]._event_postcheck_inner(page)
        assert not accepted
        assert "couldn't get past" in reason

    await scan._cleanup()


@pytest.mark.browser
@pytest.mark.asyncio
async def test_browser_fallback_dead_site(bbot_scanner, bbot_httpserver):
    """Past the challenge, the site is down: there's nothing to hand blasthttp, and the browser's answer is used."""
    browser_loads = []

    def handler(request):
        if "Firefox" not in request.headers.get("User-Agent", ""):
            return Response(CHALLENGE_PAGE, status=403, headers=CHALLENGE_HEADERS, content_type="text/html")
        browser_loads.append(request.path)
        # the challenge sets no cookie, then the site behind it doesn't answer
        if len(browser_loads) == 1:
            page = "<html><head><title>Just a moment...</title></head><body><script>setTimeout(() => location.reload(), 200)</script></body></html>"
            return Response(page, status=403, headers=CHALLENGE_HEADERS, content_type="text/html")
        return Response("<html>origin is unreachable</html>", status=522, content_type="text/html")

    bbot_httpserver.expect_request(re.compile(".*")).respond_with_handler(handler)
    scan = await browser_scan(bbot_scanner)
    web = scan.helpers.web

    response = await web.request(bbot_httpserver.url_for("/dead"), browser_fallback=True)
    assert response.status_code == 522
    assert "origin is unreachable" in response.text
    # no cookies, so no clearance kept and no blasthttp retry
    assert not web._clearances
    # blasthttp's one request (its ladder tries two profiles); no retry with cookies
    blasthttp_requests = [r for r, _ in bbot_httpserver.log if "Firefox" not in r.headers.get("User-Agent", "")]
    assert len(blasthttp_requests) == 2
    # the browser loaded it once (the challenge, then its reload), not again for a fetch
    assert browser_loads == ["/dead", "/dead"]
    await scan._cleanup()


@pytest.mark.browser
@pytest.mark.asyncio
async def test_browser_fallback_fetch(bbot_scanner, bbot_httpserver):
    """When the browser's cookies don't get blasthttp through, GETs are fetched by the browser itself."""
    serve(bbot_httpserver)
    scan = await browser_scan(bbot_scanner)
    web = scan.helpers.web
    browser = scan.helpers.browser

    # simulate a challenge whose clearance only works for the browser that earned it
    web.apply_clearance = lambda url, header_list: header_list
    solves = 0
    original_clearance = browser.clearance

    async def counting_clearance(url):
        nonlocal solves
        solves += 1
        return await original_clearance(url)

    browser.clearance = counting_clearance
    fetches = []
    original_fetch = browser.fetch

    async def counting_fetch(url):
        fetches.append(url)
        return await original_fetch(url)

    browser.fetch = counting_fetch

    response = await web.request(bbot_httpserver.url_for("/challenge"), browser_fallback=True)
    assert response.status_code == 200
    assert "past the challenge" in response.text
    # the clearance didn't work, so it isn't kept
    assert "127.0.0.1" not in web._clearances
    # the browser already loaded the URL getting past the challenge, so that's the response; it isn't loaded again
    assert fetches == []

    # a POST can't be replayed in the browser, so it gets the challenge back
    response = await web.request(bbot_httpserver.url_for("/challenge"), method="POST", browser_fallback=True)
    assert response.conclusion[0] == "needs_browser"

    # the browser solves a host's challenge for blasthttp a limited number of times, then just fetches
    for i in range(5):
        response = await web.request(bbot_httpserver.url_for(f"/challenge/{i}"), browser_fallback=True)
        assert response.status_code == 200
    assert solves == 3
    # the POST above used a solve too, so /challenge/0 got the browser's clearance load and the rest were fetched
    assert fetches == [bbot_httpserver.url_for(f"/challenge/{i}") for i in range(1, 5)]

    await scan._cleanup()


@pytest.mark.browser
@pytest.mark.asyncio
async def test_browser_fetch_any_response(bbot_scanner, bbot_httpserver, bbot_httpserver_ssl):
    """The browser's fetch follows redirects to other origins and returns responses a browser would download."""
    bbot_httpserver_ssl.expect_request("/landed").respond_with_data(
        "<html>other origin</html>", content_type="text/html"
    )
    bbot_httpserver.expect_request("/hop").respond_with_data(
        "", status=301, headers={"Location": bbot_httpserver_ssl.url_for("/landed")}
    )
    bbot_httpserver.expect_request("/report").respond_with_data(
        "a,b\n1,2\n", content_type="text/csv", headers={"Content-Disposition": "attachment; filename=report.csv"}
    )
    scan = await browser_scan(bbot_scanner)
    browser = scan.helpers.browser

    # http to https on another port: a different origin
    response = await browser.fetch(bbot_httpserver.url_for("/hop"))
    assert response.status_code == 200
    assert response.url == bbot_httpserver_ssl.url_for("/landed")
    assert "other origin" in response.text

    response = await browser.fetch(bbot_httpserver.url_for("/report"))
    assert response.status_code == 200
    assert response.text == "a,b\n1,2\n"
    await scan._cleanup()


@pytest.mark.browser
@pytest.mark.asyncio
async def test_browser_certificates(bbot_scanner, bbot_httpserver_ssl):
    """Like blasthttp, the browser doesn't verify target certificates unless web.ssl_verify_target is on."""
    bbot_httpserver_ssl.expect_request("/").respond_with_data(
        "<html><title>self-signed</title></html>", content_type="text/html"
    )
    url = bbot_httpserver_ssl.url_for("/")

    scan = await browser_scan(bbot_scanner)
    visit = await scan.helpers.browser.visit(url)
    assert visit is not None and visit.title == "self-signed"
    await scan._cleanup()

    scan = await browser_scan(bbot_scanner, ssl_verify_target=True)
    assert await scan.helpers.browser.visit(url) is None
    await scan._cleanup()
    assert await no_browser_processes()


@pytest.mark.asyncio
async def test_browser_hint(bbot_scanner, bbot_httpserver, caplog):
    """With the browser off, a scan ends by counting the URLs a challenge kept it out of."""
    serve(bbot_httpserver)
    urls = [bbot_httpserver.url_for(path) for path in ("/challenge/a", "/challenge/b", "/page")]
    scan = bbot_scanner(*urls, modules=["http"])
    [e async for e in scan.async_start()]
    assert (
        "2 URLs were skipped as they were deemed unopenable without a browser (WAF challenges). "
        "Consider re-running with -c web.enable_browser=true"
    ) in caplog.text

    # with the browser on, a fallback that's off was turned off on purpose
    scan = bbot_scanner("127.0.0.1", config={"web": {"enable_browser": True, "browser_fallback": False}})
    scan.helpers.web.unopened_urls.add(urls[0])
    assert scan.helpers.web.browser_hint() is None

    # one URL reads as one
    scan = bbot_scanner("127.0.0.1")
    scan.helpers.web.unopened_urls.add(urls[0])
    assert scan.helpers.web.browser_hint().startswith("1 URL was skipped")
