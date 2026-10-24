import os
import re
import asyncio

import psutil
from werkzeug.wrappers import Response

from ..bbot_fixtures import *
from bbot.errors import BrowserError

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


def serve(httpserver):
    """A site with a JavaScript-built page, a challenge that clears itself, and a binary file."""

    def handler(request):
        if request.path.startswith("/challenge") and request.cookies.get("cleared") != "1":
            return Response(
                CHALLENGE_PAGE,
                status=403,
                headers={"Server": "cloudflare", "cf-mitigated": "challenge"},
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
    assert bbot_httpserver.url_for("/pixel.png") in [n["url"] for n in visit.network]

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

    response = await web.request(bbot_httpserver.url_for("/challenge"), browser_fallback=True)
    assert response.status_code == 200
    assert "past the challenge" in response.text
    # the clearance didn't work, so it isn't kept
    assert "127.0.0.1" not in web._clearances

    # a POST can't be replayed in the browser, so it gets the challenge back
    response = await web.request(bbot_httpserver.url_for("/challenge"), method="POST", browser_fallback=True)
    assert response.conclusion[0] == "needs_browser"

    # the browser solves a host's challenge for blasthttp a limited number of times, then just fetches
    for i in range(5):
        response = await web.request(bbot_httpserver.url_for(f"/challenge/{i}"), browser_fallback=True)
        assert response.status_code == 200
    assert solves == 3

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
