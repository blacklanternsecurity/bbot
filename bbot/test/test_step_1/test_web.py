import re
from omegaconf import OmegaConf

from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_web_helpers(bbot_scanner, bbot_config, bbot_httpserver):
    scan1 = bbot_scanner("8.8.8.8", config=bbot_config)
    scan2 = bbot_scanner("127.0.0.1", config=bbot_config)

    user_agent = bbot_config.get("user_agent", "")
    headers = {"User-Agent": user_agent}
    custom_headers = bbot_config.get("http_headers", {})
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
    # should suceed because URL is in-scope
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
    filename = Path("/tmp/bbot_download_test_file")
    filename.unlink(missing_ok=True)
    filename2 = await scan1.helpers.download(url, filename=filename)
    assert filename2 == filename
    assert filename2.is_file()
    with open(filename2) as f:
        assert f.read() == download_content
    # 404
    path = "/test_http_helpers_download_404"
    url = bbot_httpserver.url_for(path)
    download_content = "404"
    bbot_httpserver.expect_request(uri=path).respond_with_data(download_content, status=404)
    filename = await scan1.helpers.download(url)
    assert filename is None
    assert not scan1.helpers.is_cached(url)

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
    agen = scan1.helpers.api_page_iter(template_url)
    try:
        async for result in agen:
            if result and result.text.startswith("page"):
                results.append(result)
            else:
                break
    finally:
        await agen.aclose()
    assert not results
    agen = scan1.helpers.api_page_iter(template_url, json=False)
    try:
        async for result in agen:
            if result and result.text.startswith("page"):
                results.append(result)
            else:
                break
    finally:
        await agen.aclose()
    assert [r.text for r in results] == ["page1", "page2", "page3"]


@pytest.mark.asyncio
async def test_web_interactsh(bbot_scanner, bbot_config, bbot_httpserver):
    from bbot.core.helpers.interactsh import server_list

    scan1 = bbot_scanner("8.8.8.8", config=bbot_config)

    interactsh_client = scan1.helpers.interactsh()

    async def async_callback(data):
        log.debug(f"interactsh poll: {data}")

    interactsh_domain = await interactsh_client.register(callback=async_callback)
    url = f"https://{interactsh_domain}/bbot_interactsh_test"
    response = await scan1.helpers.request(url)
    assert response.status_code == 200
    await asyncio.sleep(10)
    assert any(interactsh_domain.endswith(f"{s}") for s in server_list)
    data_list = await interactsh_client.poll()
    assert isinstance(data_list, list)
    assert any("bbot_interactsh_test" in d.get("raw-request", "") for d in data_list)
    assert await interactsh_client.deregister() is None


@pytest.mark.asyncio
async def test_web_curl(bbot_scanner, bbot_config, bbot_httpserver):
    scan = bbot_scanner("127.0.0.1", config=bbot_config)
    helpers = scan.helpers
    url = bbot_httpserver.url_for("/curl")
    bbot_httpserver.expect_request(uri="/curl").respond_with_data("curl_yep")
    bbot_httpserver.expect_request(uri="/index.html").respond_with_data("curl_yep_index")
    assert await helpers.curl(url=url) == "curl_yep"
    assert await helpers.curl(url=url, ignore_bbot_global_settings=True) == "curl_yep"
    assert (await helpers.curl(url=url, head_mode=True)).startswith("HTTP/")
    assert await helpers.curl(url=url, raw_body="body") == "curl_yep"
    assert (
        await helpers.curl(
            url=url,
            raw_path=True,
            headers={"test": "test", "test2": ["test2"]},
            ignore_bbot_global_settings=False,
            post_data={"test": "test"},
            method="POST",
            cookies={"test": "test"},
            path_override="/index.html",
        )
        == "curl_yep_index"
    )
    # test custom headers
    bbot_httpserver.expect_request("/test-custom-http-headers-curl", headers={"test": "header"}).respond_with_data(
        "curl_yep_headers"
    )
    headers_url = bbot_httpserver.url_for("/test-custom-http-headers-curl")
    curl_result = await helpers.curl(url=headers_url)
    assert curl_result == "curl_yep_headers"


@pytest.mark.asyncio
async def test_web_http_compare(httpx_mock, helpers):
    httpx_mock.add_response(url=re.compile(r"http://www\.example\.com.*"), text="wat")
    compare_helper = helpers.http_compare("http://www.example.com")
    await compare_helper.compare("http://www.example.com", headers={"asdf": "asdf"})
    await compare_helper.compare("http://www.example.com", cookies={"asdf": "asdf"})
    await compare_helper.compare("http://www.example.com", check_reflection=True)
    compare_helper.compare_body({"asdf": "fdsa"}, {"fdsa": "asdf"})
    for mode in ("getparam", "header", "cookie"):
        assert await compare_helper.canary_check("http://www.example.com", mode=mode) == True


@pytest.mark.asyncio
async def test_http_proxy(bbot_scanner, bbot_config, bbot_httpserver, proxy_server):
    endpoint = "/test_http_proxy"
    url = bbot_httpserver.url_for(endpoint)
    # test user agent + custom headers
    bbot_httpserver.expect_request(uri=endpoint).respond_with_data("test_http_proxy_yep")

    proxy_address = f"http://127.0.0.1:{proxy_server.server_address[1]}"

    test_config = OmegaConf.merge(bbot_config, OmegaConf.create({"http_proxy": proxy_address}))

    scan = bbot_scanner("127.0.0.1", config=test_config)

    assert len(proxy_server.RequestHandlerClass.urls) == 0

    r = await scan.helpers.request(url)

    assert (
        len(proxy_server.RequestHandlerClass.urls) == 1
    ), f"Request to {url} did not go through proxy {proxy_address}"
    visited_url = proxy_server.RequestHandlerClass.urls[0]
    assert visited_url.endswith(endpoint), f"There was a problem with request to {url}: {visited_url}"
    assert r.status_code == 200 and r.text == "test_http_proxy_yep"


@pytest.mark.asyncio
async def test_http_ssl(bbot_scanner, bbot_config, bbot_httpserver_ssl):
    endpoint = "/test_http_ssl"
    url = bbot_httpserver_ssl.url_for(endpoint)
    # test user agent + custom headers
    bbot_httpserver_ssl.expect_request(uri=endpoint).respond_with_data("test_http_ssl_yep")

    verify_config = OmegaConf.merge(bbot_config, OmegaConf.create({"ssl_verify": True, "http_debug": True}))
    scan1 = bbot_scanner("127.0.0.1", config=verify_config)

    not_verify_config = OmegaConf.merge(bbot_config, OmegaConf.create({"ssl_verify": False, "http_debug": True}))
    scan2 = bbot_scanner("127.0.0.1", config=not_verify_config)

    r1 = await scan1.helpers.request(url)
    assert r1 is None, "Request to self-signed SSL server went through even with ssl_verify=True"
    r2 = await scan2.helpers.request(url)
    assert r2 is not None, "Request to self-signed SSL server failed even with ssl_verify=False"
    assert r2.status_code == 200 and r2.text == "test_http_ssl_yep"
