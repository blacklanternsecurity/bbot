from ..bbot_fixtures import *  # noqa: F401
from bbot.scanner import Scanner


def test_curl(bbot_httpserver, bbot_config):
    scan = Scanner("127.0.0.1", config=bbot_config)
    helpers = scan.helpers
    url = bbot_httpserver.url_for("/curl")
    bbot_httpserver.expect_request(uri="/curl").respond_with_data("curl_yep")
    bbot_httpserver.expect_request(uri="/index.html").respond_with_data("curl_yep_index")
    assert helpers.curl(url=url) == "curl_yep"
    assert helpers.curl(url=url, ignore_bbot_global_settings=True) == "curl_yep"
    assert helpers.curl(url=url, head_mode=True).startswith("HTTP/")
    assert helpers.curl(url=url, raw_body="body") == "curl_yep"
    assert (
        helpers.curl(
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
    curl_result = helpers.curl(url=headers_url)
    assert curl_result == "curl_yep_headers"
