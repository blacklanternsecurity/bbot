import io
import json
import hashlib

import pytest
from PIL import Image

from .base import ModuleTestBase
from bbot.scanner import Scanner
from bbot.test.worker import HTTPSERVER_URL

# a big dark block whose position gives each page a distinct shape
PAGE = """<html><head><title>{title}</title></head><body style="margin:0">
<div style="position:absolute; left:{left}px; top:{top}px; width:600px; height:500px; background:#123"></div>
</body></html>"""


def read_manifest(gallery_dir):
    text = (gallery_dir / "data" / "manifest.js").read_text()
    return json.loads(text[len("bbotGallery.manifest(") : -len(");\n")])


def gallery_scan(**config):
    """A scan with the gallery, fed events directly: the browser is never used, so it isn't installed."""
    config = {"web": {"enable_browser": True}, "deps": {"behavior": "disable"}, "modules": {"gallery": config}}
    return Scanner("127.0.0.1", modules=["screenshot"], config=config)


class TestGallery(ModuleTestBase):
    pytestmark = pytest.mark.browser
    targets = [
        f"{HTTPSERVER_URL}/",
        f"{HTTPSERVER_URL}/same",
        f"{HTTPSERVER_URL}/different",
        f"{HTTPSERVER_URL}/empty",
    ]
    modules_overrides = ["http", "screenshot", "gallery"]
    config_overrides = {"web": {"enable_browser": True}}

    async def setup_after_prep(self, module_test):
        # before the scan starts there's already a gallery to open, which fills in as it goes
        gallery_dir = module_test.scan.home / "gallery"
        assert (gallery_dir / "index.html").is_file()
        assert read_manifest(gallery_dir)["total"] == 0
        assert module_test.module.open_command.endswith(str(gallery_dir / "index.html"))

        headers = {"X-Gallery-Test": "kept"}
        same = PAGE.format(title="same", left=0, top=0)
        for uri, body in (
            ("/", same),
            ("/same", same),
            ("/different", PAGE.format(title="different", left=800, top=380)),
            ("/empty", "<html><head><title>empty</title></head><body>418</body></html>"),
        ):
            module_test.set_expect_requests(
                {"uri": uri}, {"response_data": body, "content_type": "text/html", "headers": headers}
            )

    def check(self, module_test, events):
        gallery_dir = module_test.scan.home / "gallery"
        document = json.loads((gallery_dir / "gallery.json").read_text())
        shots = {s["url"]: s for s in document["screenshots"]}
        assert set(shots) == {f"{HTTPSERVER_URL}{path}" for path in ("/", "/same", "/different", "/empty")}
        assert document["levels"] == [0, 4, 8, 12]

        # identical pages share a group at every level; a different one doesn't share the tightest
        same, also_same, different = (
            shots[f"{HTTPSERVER_URL}/"],
            shots[f"{HTTPSERVER_URL}/same"],
            shots[f"{HTTPSERVER_URL}/different"],
        )
        assert same["groups"] == also_same["groups"]
        assert same["groups"][0] != different["groups"][0]
        # a near-blank page isn't grouped by its hash
        empty = shots[f"{HTTPSERVER_URL}/empty"]
        assert empty["blank"] is True and empty["groups"] is None
        assert not same["blank"]

        for shot in shots.values():
            # what the http module got for the page is joined on
            assert shot["status"] == 200
            # blasthttp gives header names in lowercase
            assert ["x-gallery-test", "kept"] in shot["headers"]
            assert shot["server"]
            # the page's links resolve from the gallery folder
            assert (gallery_dir / shot["file"]).is_file()
            assert (gallery_dir / shot["thumbnail"]).is_file()
            assert shot["discovery_path"]
        assert same["title"] == "same"
        assert document["hosts"]["127.0.0.1"]["browser_only"] is False

        # what an open page loads
        for name in ("manifest.js", "meta.js", "shots-0000.js"):
            assert (gallery_dir / "data" / name).read_text().startswith("bbotGallery.")
        manifest = read_manifest(gallery_dir)
        assert manifest["total"] == 4
        assert manifest["scan"]["status"] == "FINISHED"
        assert manifest["chunks"] == [{"file": "shots-0000.js", "rev": manifest["rev"], "count": 4}]


@pytest.mark.asyncio
async def test_gallery_joins():
    """What the rest of the scan learns about a screenshot's page and host ends up with it, whatever order it arrives in."""
    scan = gallery_scan(refresh_interval=3600)
    await scan._prep()
    gallery = scan.modules["gallery"]

    image = io.BytesIO()
    Image.new("RGB", (1440, 900), "navy").save(image, "PNG")
    png = image.getvalue()
    sha256 = hashlib.sha256(png).hexdigest()
    (scan.home / "screenshots").mkdir(parents=True, exist_ok=True)
    (scan.home / "screenshots" / f"{sha256}.png").write_bytes(png)

    url = "http://127.0.0.1:8888/login"
    page = scan.make_event(url, "URL", parent=scan.root_event, tags=["status-200"])
    redirect = scan.make_event("http://127.0.0.1:8888/next", "URL_UNVERIFIED", parent=page, tags=["js-redirect"])
    shot = scan.make_event(
        {
            "url": url,
            "path": f"screenshots/{sha256}.png",
            "sha256": sha256,
            "size": len(png),
            "mime_type": "image/png",
            "width": 1440,
            "height": 900,
            "dhash": "00000000000000ff",
            "blank": False,
        },
        "WEBSCREENSHOT",
        parent=page,
    )
    # the response arrives after the screenshot
    response = scan.make_event(
        {
            "url": url,
            "input": "127.0.0.1:8888",
            "status_code": 200,
            "method": "GET",
            "path": "/login",
            "host": "127.0.0.1",
            "title": "Sign in",
            "content_type": "text/html",
            "header": {"server": "nginx"},
            "raw_header": "HTTP/1.1 200 \r\nServer: nginx\r\nX-Frame-Options: DENY\r\n\r\n",
            "body": "",
            "cert_info": {"common_name": "login.test", "sans": ["login.test"], "issuer": "Test CA"},
        },
        "HTTP_RESPONSE",
        parent=page,
        tags=["in-scope"],
    )
    technology = scan.make_event({"host": "127.0.0.1", "technology": "nginx"}, "TECHNOLOGY", parent=page)
    finding = scan.make_event(
        {
            "host": "127.0.0.1",
            "url": url,
            "name": "Test",
            "description": "a test finding",
            "severity": "HIGH",
            "confidence": "HIGH",
        },
        "FINDING",
        parent=page,
    )
    waf = scan.make_event({"host": "127.0.0.1", "url": url, "waf": "Test WAF"}, "WAF", parent=page)
    for event in (redirect, shot, response, technology, finding, waf):
        await gallery.handle_event(event)
    await gallery.report()

    document = json.loads((gallery.gallery_dir / "gallery.json").read_text())
    [record] = document["screenshots"]
    assert record["title"] == "Sign in"
    assert record["server"] == "nginx"
    assert ["X-Frame-Options", "DENY"] in record["headers"]
    assert record["cert"]["common_name"] == "login.test"
    assert record["js_redirect"] == "http://127.0.0.1:8888/next"
    assert (gallery.gallery_dir / record["thumbnail"]).is_file()

    host = document["hosts"]["127.0.0.1"]
    assert host["technologies"] == ["nginx"]
    assert host["wafs"] == ["Test WAF"]
    [finding_data] = document["findings"]
    assert host["findings"] == [finding_data["id"]]
    assert finding_data["severity"] == "HIGH"
    await scan._cleanup()


@pytest.mark.asyncio
async def test_gallery_grouping():
    scan = gallery_scan()
    await scan._prep()
    gallery = scan.modules["gallery"]

    base = 0
    three_off = 0b111
    ten_off = 0b1111111111
    assert gallery._group(f"{base:016x}", False) == [0, 0, 0, 0]
    # 3 bits away: apart only at the exact level
    assert gallery._group(f"{three_off:016x}", False) == [1, 0, 0, 0]
    # 10 bits from the first group's founder: together only at the loosest level
    assert gallery._group(f"{ten_off:016x}", False) == [2, 1, 1, 0]
    # an identical hash joins the existing groups
    assert gallery._group(f"{three_off:016x}", False) == [1, 0, 0, 0]
    assert gallery._group("0" * 16, True) is None
    await scan._cleanup()


@pytest.mark.asyncio
async def test_gallery_live_updates():
    """During the scan only what changed is rewritten, so an open page reloads as little as possible."""
    scan = gallery_scan(refresh_interval=3600)
    await scan._prep()
    gallery = scan.modules["gallery"]
    gallery.chunk_size = 2

    image = io.BytesIO()
    Image.new("RGB", (1440, 900), "navy").save(image, "PNG")
    png = image.getvalue()
    sha256 = hashlib.sha256(png).hexdigest()
    (scan.home / "screenshots").mkdir(parents=True, exist_ok=True)
    (scan.home / "screenshots" / f"{sha256}.png").write_bytes(png)

    def manifest():
        return read_manifest(gallery.gallery_dir)

    async def screenshot(n):
        url = f"http://127.0.0.1:8888/{n}"
        page = scan.make_event(url, "URL", parent=scan.root_event, tags=["status-200"])
        data = {"url": url, "path": f"screenshots/{sha256}.png", "sha256": sha256, "size": len(png)}
        data.update({"mime_type": "image/png", "width": 1440, "height": 900, "dhash": "0" * 16, "blank": False})
        await gallery.handle_event(scan.make_event(data, "WEBSCREENSHOT", parent=page))

    for n in range(3):
        await screenshot(n)
    gallery._flush()
    first = manifest()
    assert first["total"] == 3
    assert [(c["file"], c["count"]) for c in first["chunks"]] == [("shots-0000.js", 2), ("shots-0001.js", 1)]

    # nothing new, nothing written
    gallery._flush()
    assert manifest()["rev"] == first["rev"]

    # a new screenshot rewrites only the chunk it lands in
    await screenshot(3)
    gallery._flush()
    second = manifest()
    assert second["rev"] == first["rev"] + 1
    assert second["chunks"][0]["rev"] == first["chunks"][0]["rev"]
    assert second["chunks"][1]["rev"] == second["rev"]
    assert second["generation"] == first["generation"]

    # a late response for an old screenshot rewrites its chunk
    response = scan.make_event(
        {
            "url": "http://127.0.0.1:8888/0",
            "status_code": 200,
            "title": "late",
            "content_type": "text/html",
            "raw_header": "HTTP/1.1 200 \r\n\r\n",
            "body": "",
        },
        "HTTP_RESPONSE",
        parent=scan.root_event,
        tags=["in-scope"],
    )
    await gallery.handle_event(response)
    gallery._flush()
    assert manifest()["chunks"][0]["rev"] == second["rev"] + 1
    await scan._cleanup()
