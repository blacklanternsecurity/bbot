import re

from blasthttp import HTTPStatusError

from ..bbot_fixtures import *

from bbot.test.worker import BBOT_TEST_DIR, HTTPSERVER_HOSTPORT


@pytest.mark.asyncio
async def test_web(bbot_scanner, bbot_httpserver, blasthttp_mock):
    from werkzeug.wrappers import Response

    def server_handler(request):
        return Response(f"{request.url}: {request.headers}")

    base_url = bbot_httpserver.url_for("/test/")
    bbot_httpserver.expect_request(uri=re.compile(r"/test/\d+")).respond_with_handler(server_handler)
    bbot_httpserver.expect_request(uri=re.compile(r"/nope")).respond_with_data("nope", status=500)

    scan = bbot_scanner()
    await scan._prep()

    # request
    response = await scan.helpers.request(f"{base_url}1")
    assert response.status_code == 200
    assert response.text.startswith(f"{base_url}1: ")

    num_urls = 100

    # request_batch_stream
    urls = [f"{base_url}{i}" for i in range(num_urls)]
    responses = []
    async for url, response in scan.helpers.request_batch_stream(urls):
        responses.append((url, response))
    assert len(responses) == 100
    assert all(r[1].status_code == 200 and r[1].text.startswith(f"{r[0]}: ") for r in responses)

    # request_batch_stream with tracker
    urls_and_kwargs = [(urls[i], {"headers": {f"h{i}": f"v{i}"}}, i) for i in range(num_urls)]
    seen_trackers = set()
    async for url, response, custom_tracker in scan.helpers.request_batch_stream(urls_and_kwargs):
        assert response.status_code == 200
        assert response.text.startswith(f"{url}: ")
        seen_trackers.add(custom_tracker)
    assert seen_trackers == set(range(num_urls))

    # request with raise_error=True
    with pytest.raises(WebError):
        await scan.helpers.request("http://www.example.com/", raise_error=True)
    try:
        await scan.helpers.request("http://www.example.com/", raise_error=True)
    except WebError as e:
        assert hasattr(e, "response")
        assert e.response is None
    with pytest.raises(HTTPStatusError):
        response = await scan.helpers.request(bbot_httpserver.url_for("/nope"), raise_error=True)
        response.raise_for_status()
    try:
        response = await scan.helpers.request(bbot_httpserver.url_for("/nope"), raise_error=True)
        response.raise_for_status()
    except HTTPStatusError as e:
        assert hasattr(e, "response")
        assert e.response.status_code == 500

    # download
    url = f"{base_url}999"
    filename = await scan.helpers.download(url)
    file_content = open(filename).read()
    assert file_content.startswith(f"{url}: ")

    # download with raise_error=True
    with pytest.raises(WebError):
        await scan.helpers.download("http://www.example.com/", raise_error=True)
    try:
        await scan.helpers.download("http://www.example.com/", raise_error=True)
    except WebError as e:
        assert hasattr(e, "response")
        assert e.response is None
    with pytest.raises(WebError):
        await scan.helpers.download(bbot_httpserver.url_for("/nope"), raise_error=True)
    try:
        await scan.helpers.download(bbot_httpserver.url_for("/nope"), raise_error=True)
    except WebError as e:
        assert hasattr(e, "response")
        assert e.response.status_code == 500

    await scan._cleanup()


@pytest.mark.asyncio
async def test_web_request_files_multipart(bbot_scanner, bbot_httpserver):
    """httpx-style files= kwarg builds a multipart/form-data body."""
    captured = {}

    def server_handler(request):
        from werkzeug.wrappers import Response

        captured["body"] = request.get_data()
        captured["content_type"] = request.headers.get("Content-Type", "")
        return Response("ok")

    bbot_httpserver.expect_request(uri="/upload", method="POST").respond_with_handler(server_handler)
    url = bbot_httpserver.url_for("/upload")

    scan = bbot_scanner()
    await scan._prep()

    response = await scan.helpers.request(
        url,
        method="POST",
        files={
            "field": (None, "value"),
            "f": ("blob", b"\x00\x01\x02hello", "application/octet-stream"),
        },
    )
    assert response.status_code == 200

    ct = captured["content_type"]
    assert ct.startswith("multipart/form-data; boundary=")
    body = captured["body"]
    assert b'name="field"' in body
    assert b"value" in body
    assert b'filename="blob"' in body
    assert b"\x00\x01\x02hello" in body

    await scan._cleanup()


@pytest.mark.asyncio
async def test_web_request_rejects_conflicting_body_kwargs(bbot_scanner):
    scan = bbot_scanner()
    await scan._prep()
    url = "http://example.com/"

    pairs = [
        {"json": {"a": 1}, "files": {"f": ("x", b"x")}},
        {"json": {"a": 1}, "data": {"a": "b"}},
        {"body": "raw", "json": {"a": 1}},
        {"body": "raw", "data": {"a": "b"}},
        {"body": "raw", "files": {"f": ("x", b"x")}},
        {"data": {"a": "b"}, "files": {"f": ("x", b"x")}},
    ]
    for kwargs in pairs:
        with pytest.raises(ValueError, match="conflicting body kwargs"):
            await scan.helpers.request(url, method="POST", **kwargs)

    await scan._cleanup()


@pytest.mark.asyncio
async def test_web_helpers(bbot_scanner, bbot_httpserver, blasthttp_mock):
    # json conversion
    scan = bbot_scanner("evilcorp.com")
    await scan._prep()
    url = "http://www.evilcorp.com/json_test?a=b"
    blasthttp_mock.add_response(url=url, text="hello\nworld")
    response = await scan.helpers.web.request(url)
    j = scan.helpers.response_to_json(response)
    assert j["status_code"] == 200
    assert j["host"] == "www.evilcorp.com"
    assert j["scheme"] == "http"
    assert j["method"] == "GET"
    assert j["port"] == 80
    assert j["path"] == "/json_test"
    assert j["body"] == "hello\nworld"
    assert j["content_type"] == "text/plain"
    assert j["url"] == "http://www.evilcorp.com/json_test?a=b"

    await scan._cleanup()

    scan1 = bbot_scanner("8.8.8.8", modules=["ipneighbor"])
    scan2 = bbot_scanner("127.0.0.1")

    await scan1._prep()
    await scan2._prep()
    module = scan1.modules["ipneighbor"]

    web_config = CORE.config.get("web", {})
    user_agent = web_config.get("user_agent", "")
    headers = {"User-Agent": user_agent}
    custom_headers = web_config.get("http_headers", {})
    headers.update(custom_headers)
    assert headers["test"] == "header"

    url = bbot_httpserver.url_for("/test_http_helpers")
    # test user agent + custom headers
    bbot_httpserver.expect_request(uri="/test_http_helpers", headers=headers).respond_with_data(
        "test_http_helpers_yep"
    )
    response = await scan1.helpers.request(url)
    # should fail because URL is not in-scope
    assert response.status_code == 500
    response = await scan2.helpers.request(url)
    # should succeed because URL is in-scope
    assert response.status_code == 200
    assert response.text == "test_http_helpers_yep"

    # download file
    path = "/test_http_helpers_download"
    url = bbot_httpserver.url_for(path)
    download_content = "test_http_helpers_download_yep"
    bbot_httpserver.expect_request(uri=path).respond_with_data(download_content)
    filename = await scan1.helpers.download(url)
    assert Path(str(filename)).is_file()
    assert scan1.helpers.is_cached(url)
    with open(filename) as f:
        assert f.read() == download_content
    filename = BBOT_TEST_DIR / "bbot_download_test_file"
    filename.unlink(missing_ok=True)
    filename2 = await scan1.helpers.download(url, filename=filename)
    assert filename2 == filename
    assert filename2.is_file()
    with open(filename2) as f:
        assert f.read() == download_content

    # beautifulsoup
    download_content = """
    <div>
    <h1>Example Domain</h1>
    <p>This domain is for use in illustrative examples in documents. You may use this
    domain in literature without prior coordination or asking for permission.</p>
    <p><a href="https://www.iana.org/domains/example">More information...</a></p>
    </div>
    """

    path = "/test_http_helpers_beautifulsoup"
    url = bbot_httpserver.url_for(path)
    bbot_httpserver.expect_request(uri=path).respond_with_data(download_content, status=200)
    webpage = await scan1.helpers.request(url)
    assert webpage, "Webpage is False"
    soup = scan1.helpers.beautifulsoup(webpage, "html.parser")
    assert soup, "Soup is False"
    # pretty_print = soup.prettify()
    # assert pretty_print, f"PrettyPrint is False"
    # scan1.helpers.log.info(f"{pretty_print}")
    html_text = soup.find(text="Example Domain")
    assert html_text, "Find HTML Text is False"

    # 404
    path = "/test_http_helpers_download_404"
    url = bbot_httpserver.url_for(path)
    download_content = "404"
    bbot_httpserver.expect_request(uri=path).respond_with_data(download_content, status=404)
    filename = await scan1.helpers.download(url)
    assert filename is None
    assert not scan1.helpers.is_cached(url)
    with pytest.raises(WebError):
        filename = await scan1.helpers.download(url, raise_error=True)

    # wordlist
    path = "/test_http_helpers_wordlist"
    url = bbot_httpserver.url_for(path)
    download_content = "a\ncool\nword\nlist"
    bbot_httpserver.expect_request(uri=path).respond_with_data(download_content)
    filename = await scan1.helpers.wordlist(url)
    assert Path(str(filename)).is_file()
    assert scan1.helpers.is_cached(url)
    assert list(scan1.helpers.read_file(filename)) == ["a", "cool", "word", "list"]

    # page iteration
    base_path = "/test_http_page_iteration"
    template_path = base_path + "/{page}?page_size={page_size}&offset={offset}"
    template_url = bbot_httpserver.url_for(template_path)
    bbot_httpserver.expect_request(
        uri=f"{base_path}/1", query_string={"page_size": "100", "offset": "0"}
    ).respond_with_data("page1")
    bbot_httpserver.expect_request(
        uri=f"{base_path}/2", query_string={"page_size": "100", "offset": "100"}
    ).respond_with_data("page2")
    bbot_httpserver.expect_request(
        uri=f"{base_path}/3", query_string={"page_size": "100", "offset": "200"}
    ).respond_with_data("page3")
    results = []
    agen = module.api_page_iter(template_url)
    try:
        async for result in agen:
            if result and result.text.startswith("page"):
                results.append(result)
            else:
                break
    finally:
        await agen.aclose()
    assert not results
    agen = module.api_page_iter(template_url, _json=False)
    try:
        async for result in agen:
            if result and result.text.startswith("page"):
                results.append(result)
            else:
                break
    finally:
        await agen.aclose()
    assert [r.text for r in results] == ["page1", "page2", "page3"]

    await scan1._cleanup()
    await scan2._cleanup()


@pytest.mark.asyncio
async def test_web_interactsh(bbot_scanner, bbot_httpserver):
    from bbot.core.helpers.interactsh import server_list

    sync_called = False
    async_called = False

    sync_correct_url = False
    async_correct_url = False

    scan1 = bbot_scanner("8.8.8.8")
    await scan1._prep()
    await scan1._set_status("RUNNING")

    interactsh_client = scan1.helpers.interactsh(poll_interval=3)
    interactsh_client2 = scan1.helpers.interactsh(poll_interval=3)

    async def async_callback(data):
        nonlocal async_called
        nonlocal async_correct_url
        async_called = True
        d = data.get("raw-request", "")
        async_correct_url |= "bbot_interactsh_test" in d
        log.debug(f"interactsh poll (async): {d}")

    def sync_callback(data):
        nonlocal sync_called
        nonlocal sync_correct_url
        sync_called = True
        d = data.get("raw-request", "")
        sync_correct_url |= "bbot_interactsh_test" in d
        log.debug(f"interactsh poll (sync): {d}")

    interactsh_domain = await interactsh_client.register(callback=async_callback)
    url = f"http://{interactsh_domain}/bbot_interactsh_test"
    response = await scan1.helpers.request(url)
    assert response.status_code == 200
    assert any(interactsh_domain.endswith(f"{s}") for s in server_list)

    interactsh_domain2 = await interactsh_client2.register(callback=sync_callback)
    url2 = f"http://{interactsh_domain2}/bbot_interactsh_test"
    response2 = await scan1.helpers.request(url2)
    assert response2.status_code == 200
    assert any(interactsh_domain2.endswith(f"{s}") for s in server_list)

    await asyncio.sleep(10)

    data_list = await interactsh_client.poll()
    data_list2 = await interactsh_client2.poll()
    assert isinstance(data_list, list)
    assert isinstance(data_list2, list)

    assert await interactsh_client.deregister() is None
    assert await interactsh_client2.deregister() is None

    assert sync_called, "Interactsh synchrononous callback was not called"
    assert async_called, "Interactsh async callback was not called"

    assert sync_correct_url, f"Data content was not correct for {url2}"
    assert async_correct_url, f"Data content was not correct for {url}"

    await scan1._cleanup()


@pytest.mark.asyncio
async def test_web_request_target(bbot_scanner, bbot_httpserver):
    """Test request() with request_target, ignore_bbot_global_settings, and other advanced kwargs."""
    scan = bbot_scanner("127.0.0.1")
    await scan._prep()
    helpers = scan.helpers
    url = bbot_httpserver.url_for("/test-advanced")
    bbot_httpserver.expect_request(uri="/test-advanced").respond_with_data("advanced_yep")
    bbot_httpserver.expect_request(uri="/index.html").respond_with_data("index_yep")

    # basic request
    r = await helpers.request(url=url)
    assert r.text == "advanced_yep"

    # ignore_bbot_global_settings
    r = await helpers.request(url=url, ignore_bbot_global_settings=True)
    assert r.text == "advanced_yep"

    # HEAD method
    r = await helpers.request(url=url, method="HEAD")
    assert r.status_code == 200

    # body kwarg
    r = await helpers.request(url=url, body="body")
    assert r.text == "advanced_yep"

    # request_target overrides the HTTP request-line path
    r = await helpers.request(
        url=url,
        headers={"test": "test", "test2": ["test2"]},
        data={"test": "test"},
        method="POST",
        cookies={"test": "test"},
        request_target="/index.html",
    )
    assert r.text == "index_yep"

    # test custom headers from scan config
    bbot_httpserver.expect_request("/test-custom-http-headers-advanced", headers={"test": "header"}).respond_with_data(
        "headers_yep"
    )
    headers_url = bbot_httpserver.url_for("/test-custom-http-headers-advanced")
    r = await helpers.request(url=headers_url)
    assert r.text == "headers_yep"

    await scan._cleanup()


@pytest.mark.asyncio
async def test_web_http_compare(blasthttp_mock, bbot_scanner):
    scan = bbot_scanner()
    await scan._prep()
    helpers = scan.helpers
    blasthttp_mock.add_response(url=re.compile(r"http://www\.example\.com.*"), text="wat")
    compare_helper = helpers.http_compare("http://www.example.com")
    await compare_helper.compare("http://www.example.com", headers={"asdf": "asdf"})
    await compare_helper.compare("http://www.example.com", cookies={"asdf": "asdf"})
    await compare_helper.compare("http://www.example.com", check_reflection=True)
    compare_helper.compare_body({"asdf": "fdsa"}, {"fdsa": "asdf"})
    for mode in ("getparam", "header", "cookie"):
        assert await compare_helper.canary_check("http://www.example.com", mode=mode) is True

    await scan._cleanup()


@pytest.mark.asyncio
async def test_http_proxy(bbot_scanner, bbot_httpserver, proxy_server):
    endpoint = "/test_http_proxy"
    url = bbot_httpserver.url_for(endpoint)
    # test user agent + custom headers
    bbot_httpserver.expect_request(uri=endpoint).respond_with_data("test_http_proxy_yep")

    proxy_address = f"http://127.0.0.1:{proxy_server.server_address[1]}"

    scan = bbot_scanner("127.0.0.1", config={"web": {"http_proxy": proxy_address}})
    await scan._prep()

    assert len(proxy_server.RequestHandlerClass.urls) == 0

    r = await scan.helpers.request(url)

    assert len(proxy_server.RequestHandlerClass.urls) == 1, (
        f"Request to {url} did not go through proxy {proxy_address}"
    )
    visited_url = proxy_server.RequestHandlerClass.urls[0]
    assert visited_url.endswith(endpoint), f"There was a problem with request to {url}: {visited_url}"
    assert r.status_code == 200 and r.text == "test_http_proxy_yep"

    await scan._cleanup()


@pytest.mark.asyncio
async def test_http_proxy_exclude(bbot_scanner, bbot_httpserver, proxy_server):
    """Verify that requests to excluded hosts bypass the proxy."""
    endpoint = "/test_http_proxy_exclude"
    url = bbot_httpserver.url_for(endpoint)
    bbot_httpserver.expect_request(uri=endpoint).respond_with_data("proxy_exclude_works")

    proxy_address = f"http://127.0.0.1:{proxy_server.server_address[1]}"
    # Exclude 127.0.0.1 from proxy
    scan = bbot_scanner(
        "127.0.0.1",
        config={
            "web": {
                "http_proxy": proxy_address,
                "http_proxy_exclude": ["127.0.0.1"],
            }
        },
    )

    await scan._prep()

    proxy_server.RequestHandlerClass.urls.clear()
    r = await scan.helpers.request(url)

    # Request should NOT go through proxy
    assert len(proxy_server.RequestHandlerClass.urls) == 0, "Request should have bypassed proxy but went through it"
    assert r.status_code == 200 and r.text == "proxy_exclude_works"

    await scan._cleanup()


@pytest.mark.asyncio
async def test_http_proxy_exclude_passthrough(bbot_scanner, bbot_httpserver, proxy_server):
    """Verify that non-excluded hosts still go through the proxy."""
    endpoint = "/test_proxy_passthrough"
    url = bbot_httpserver.url_for(endpoint)
    bbot_httpserver.expect_request(uri=endpoint).respond_with_data("passthrough_works")

    proxy_address = f"http://127.0.0.1:{proxy_server.server_address[1]}"
    # Exclude a different host, not the one we're requesting
    scan = bbot_scanner(
        "127.0.0.1",
        config={
            "web": {
                "http_proxy": proxy_address,
                "http_proxy_exclude": ["10.0.0.0/8"],
            }
        },
    )

    await scan._prep()

    proxy_server.RequestHandlerClass.urls.clear()
    r = await scan.helpers.request(url)

    # Request SHOULD go through proxy (127.0.0.1 not in exclusion list)
    assert len(proxy_server.RequestHandlerClass.urls) == 1, (
        f"Request to {url} should have gone through proxy but didn't"
    )
    assert r.status_code == 200 and r.text == "passthrough_works"

    await scan._cleanup()


@pytest.mark.asyncio
async def test_http_ssl(bbot_scanner, bbot_httpserver_ssl):
    endpoint = "/test_http_ssl"
    url = bbot_httpserver_ssl.url_for(endpoint)
    # test user agent + custom headers
    bbot_httpserver_ssl.expect_request(uri=endpoint).respond_with_data("test_http_ssl_yep")

    # ssl_verify_target controls target-directed traffic
    scan1 = bbot_scanner("127.0.0.1", config={"web": {"ssl_verify_target": True, "debug": True}})
    scan2 = bbot_scanner("127.0.0.1", config={"web": {"ssl_verify_target": False, "debug": True}})
    await scan1._prep()
    await scan2._prep()

    r1 = await scan1.helpers.request(url)
    assert r1 is None, "Request to self-signed SSL server went through even with ssl_verify_target=True"
    r2 = await scan2.helpers.request(url)
    assert r2 is not None, "Request to self-signed SSL server failed even with ssl_verify_target=False"
    assert r2.status_code == 200 and r2.text == "test_http_ssl_yep"

    await scan1._cleanup()
    await scan2._cleanup()

    # ssl_verify per-request override (used by infrastructure callers like api_request/download)
    scan3 = bbot_scanner("127.0.0.1", config={"web": {"ssl_verify_target": True, "debug": True}})
    await scan3._prep()
    r3 = await scan3.helpers.request(url, ssl_verify=False)
    assert r3 is not None, "Per-request ssl_verify=False override did not bypass verification"
    assert r3.status_code == 200 and r3.text == "test_http_ssl_yep"
    await scan3._cleanup()


@pytest.mark.asyncio
async def test_web_cookies(bbot_scanner, bbot_httpserver):
    from werkzeug.wrappers import Response

    def set_cookie_handler(request):
        resp = Response("ok")
        resp.set_cookie("wat", "asdf", path="/")
        return resp

    def echo_cookies_handler(request):
        cookies = request.cookies
        cookie_str = "; ".join([f"{key}={value}" for key, value in cookies.items()])
        return Response(f"Cookies: {cookie_str}")

    bbot_httpserver.expect_request(uri="/setcookie").respond_with_handler(set_cookie_handler)
    bbot_httpserver.expect_request(uri="/echocookie").respond_with_handler(echo_cookies_handler)

    scan = bbot_scanner("127.0.0.1")
    await scan._prep()

    # make sure Set-Cookie headers are parsed in the response
    r = await scan.helpers.request(bbot_httpserver.url_for("/setcookie"))
    assert r is not None
    assert r.cookies.get("wat") == "asdf"

    # blasthttp does NOT persist cookies across requests (stateless by design)
    r2 = await scan.helpers.request(bbot_httpserver.url_for("/echocookie"))
    assert r2 is not None
    assert "wat=asdf" not in r2.text

    # but manually sending cookies should work
    r3 = await scan.helpers.request(bbot_httpserver.url_for("/echocookie"), cookies={"wat": "asdf"})
    assert r3 is not None
    assert "wat=asdf" in r3.text

    # make sure multiple cookies are sent
    r4 = await scan.helpers.request(bbot_httpserver.url_for("/echocookie"), cookies={"foo": "bar", "baz": "qux"})
    assert r4 is not None
    assert "foo=bar" in r4.text
    assert "baz=qux" in r4.text

    await scan._cleanup()


@pytest.mark.asyncio
async def test_web_redirect_cookies(bbot_scanner, bbot_httpserver):
    from werkzeug.wrappers import Response

    def login_handler(request):
        resp = Response("redirecting", status=302)
        resp.headers["Location"] = "/dashboard"
        resp.set_cookie("session", "abc123", path="/")
        return resp

    def dashboard_handler(request):
        cookie_str = "; ".join([f"{key}={value}" for key, value in request.cookies.items()])
        return Response(f"Cookies: {cookie_str}")

    bbot_httpserver.expect_request(uri="/login").respond_with_handler(login_handler)
    bbot_httpserver.expect_request(uri="/dashboard").respond_with_handler(dashboard_handler)

    scan = bbot_scanner("127.0.0.1")
    await scan._prep()

    # a cookie set by one redirect hop is sent on the hops that follow it
    r1 = await scan.helpers.request(bbot_httpserver.url_for("/login"), follow_redirects=True)
    assert r1 is not None
    assert r1.status_code == 200
    assert "session=abc123" in r1.text

    # what the chain collects lives for that request only; it does not leak into the next one
    r2 = await scan.helpers.request(bbot_httpserver.url_for("/dashboard"))
    assert r2 is not None
    assert "session=abc123" not in r2.text

    # a cookie the caller set wins over a Set-Cookie of the same name from the chain
    r3 = await scan.helpers.request(
        bbot_httpserver.url_for("/login"), follow_redirects=True, cookies={"session": "mine"}
    )
    assert r3 is not None
    assert "session=mine" in r3.text
    assert "abc123" not in r3.text

    # redirect_cookies=False reverts to not carrying them
    r4 = await scan.helpers.request(bbot_httpserver.url_for("/login"), follow_redirects=True, redirect_cookies=False)
    assert r4 is not None
    assert "session=abc123" not in r4.text

    await scan._cleanup()


@pytest.mark.asyncio
async def test_web_decode_error(bbot_scanner, bbot_httpserver):
    import gzip
    from werkzeug.wrappers import Response

    from bbot.core.helpers.web.response_event import response_to_event_dict

    def lying_handler(request):
        resp = Response(b"<title>not actually gzipped</title>")
        resp.headers["Content-Encoding"] = "gzip"
        return resp

    def honest_handler(request):
        resp = Response(gzip.compress(b"<title>real body</title>"))
        resp.headers["Content-Encoding"] = "gzip"
        return resp

    bbot_httpserver.expect_request(uri="/lying").respond_with_handler(lying_handler)
    bbot_httpserver.expect_request(uri="/honest").respond_with_handler(honest_handler)

    scan = bbot_scanner("127.0.0.1")
    await scan._prep()

    # a body that doesn't match its declared Content-Encoding is kept, not dropped,
    # and comes with a reason saying the bytes are not decoded content
    r1 = await scan.helpers.request(bbot_httpserver.url_for("/lying"))
    assert r1 is not None
    assert r1.status_code == 200
    assert r1.decode_error

    # both HTTP_RESPONSE dict builders carry that reason forward
    j1 = response_to_event_dict(r1, HTTPSERVER_HOSTPORT)
    assert j1["decode_error"] == r1.decode_error
    assert scan.helpers.response_to_json(r1)["decode_error"] == r1.decode_error

    # those bytes are not content, so they are not offered as a body or a title
    assert j1["body"] == ""
    assert j1["title"] == ""
    assert "not actually gzipped" not in str(j1)
    event1 = scan.make_event(j1, "HTTP_RESPONSE", parent=scan.root_event)
    assert not event1.body

    # a body that does match its Content-Encoding is ordinary content
    r2 = await scan.helpers.request(bbot_httpserver.url_for("/honest"))
    assert r2 is not None
    assert r2.decode_error is None
    j2 = response_to_event_dict(r2, HTTPSERVER_HOSTPORT)
    assert "decode_error" not in j2
    assert "decode_error" not in scan.helpers.response_to_json(r2)
    event2 = scan.make_event(j2, "HTTP_RESPONSE", parent=scan.root_event)
    assert event2.data["title"] == "real body"

    await scan._cleanup()


@pytest.mark.asyncio
async def test_http_sendcookies(bbot_scanner, bbot_httpserver):
    endpoint = "/"
    url = bbot_httpserver.url_for(endpoint)
    from werkzeug.wrappers import Response

    def echo_cookies_handler(request):
        cookies = request.cookies
        cookie_str = "; ".join([f"{key}={value}" for key, value in cookies.items()])
        return Response(f"Echoed Cookies: {cookie_str}\nEchoed Headers: {request.headers}")

    bbot_httpserver.expect_request(uri=endpoint).respond_with_handler(echo_cookies_handler)
    scan1 = bbot_scanner("127.0.0.1", config={"web": {"debug": True}})
    await scan1._prep()
    r1 = await scan1.helpers.request(url, cookies={"foo": "bar"})

    assert r1 is not None, "Request to self-signed SSL server went through even with ssl_verify=True"
    assert "bar" in r1.text
    await scan1._cleanup()


@pytest.mark.asyncio
async def test_api_download_api_key_cycle(bbot_scanner, bbot_httpserver):
    from werkzeug.wrappers import Response
    from bbot.modules.base import BaseModule

    endpoint = "/api_download_cycle_one_test"
    url = bbot_httpserver.url_for(endpoint)

    seen_auth = []
    n_request = 0

    # First key should trigger 500, second key should succeed with 200
    def handler(request):
        nonlocal n_request
        n_request += 1
        auth = request.headers.get("Authorization", "")
        seen_auth.append(auth)
        if auth == "Bearer k1":
            if n_request == 1:
                return Response("ok_k1", status=200)
            return Response("fail_k1", status=500)
        elif auth == "Bearer k2":
            return Response("ok_k2", status=200)
        return Response("unexpected_key", status=400)

    bbot_httpserver.expect_request(uri=endpoint).respond_with_handler(handler)

    scan = bbot_scanner("127.0.0.1")
    await scan._prep()
    module = BaseModule(scan)
    module.api_key = ["k1", "k2"]

    filename = await module.api_download(url)
    assert filename is not None
    with open(filename) as f:
        assert f.read() == "ok_k1"

    assert seen_auth == ["Bearer k1"]

    filename = await module.api_download(url)

    # verify the requests occurred in expected order with expected API keys
    assert seen_auth == ["Bearer k1", "Bearer k1", "Bearer k2"]

    await scan._cleanup()


@pytest.mark.asyncio
async def test_is_http_wildcard_host(bbot_scanner):
    """Test is_http_wildcard_host caching, retry, and return value semantics."""
    scan = bbot_scanner()
    await scan._prep()

    web = scan.helpers.web
    probe_results = []

    async def mock_probe(scheme, host, port):
        return probe_results.pop(0)

    web._probe_wildcard_host = mock_probe

    # wildcard host: probe returns a truthy sentinel
    probe_results.append("WILDCARD_CMP")
    result = await web.is_http_wildcard_host("https", "spa.example.com", 443)
    assert result == "WILDCARD_CMP"
    # cached: no more probe calls needed
    result2 = await web.is_http_wildcard_host("https", "spa.example.com", 443)
    assert result2 == "WILDCARD_CMP"

    # non-wildcard host: probe returns False
    probe_results.append(False)
    result = await web.is_http_wildcard_host("https", "normal.example.com", 443)
    assert result is False

    # retry once on first failure, succeed on second
    probe_results.extend(["retry", "WILDCARD_RETRY"])
    result = await web.is_http_wildcard_host("https", "flaky.example.com", 443)
    assert result == "WILDCARD_RETRY"

    # both attempts fail: caches None
    probe_results.extend(["retry", "retry"])
    result = await web.is_http_wildcard_host("https", "down.example.com", 443)
    assert result is None
    # cached as None
    result2 = await web.is_http_wildcard_host("https", "down.example.com", 443)
    assert result2 is None

    await scan._cleanup()
