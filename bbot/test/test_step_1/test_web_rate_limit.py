import time

from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_web_rate_limit(bbot_scanner, bbot_httpserver):
    """Verify that http_rate_limit throttles requests to the configured RPS."""
    bbot_httpserver.expect_request(uri="/rate_limit_test").respond_with_data("ok")

    # 10 requests per second = ~100ms between requests
    rps = 10
    num_requests = 20
    scan = bbot_scanner("127.0.0.1", config={"web": {"http_rate_limit": rps}})
    await scan._prep()

    # verify the rate limit was applied to the blasthttp client
    assert scan.helpers.web.client is scan.helpers.blasthttp

    url = bbot_httpserver.url_for("/rate_limit_test")
    request_times = []
    for _ in range(num_requests):
        r = await scan.helpers.request(url)
        request_times.append(time.monotonic())
        assert r.status_code == 200

    elapsed = request_times[-1] - request_times[0]
    # at 10 rps, 20 requests should take at least ~1.9 seconds
    # (19 intervals at 100ms each)
    # use a conservative lower bound to avoid flakiness
    min_expected = (num_requests - 1) / rps * 0.7
    assert elapsed >= min_expected, (
        f"Rate limiting not working: {num_requests} requests completed in {elapsed:.2f}s "
        f"(expected >= {min_expected:.2f}s at {rps} rps)"
    )

    await scan._cleanup()


@pytest.mark.asyncio
async def test_web_no_rate_limit(bbot_scanner, bbot_httpserver):
    """Verify that with no rate limit (default), requests are not throttled."""
    bbot_httpserver.expect_request(uri="/no_rate_limit_test").respond_with_data("ok")

    num_requests = 20
    scan = bbot_scanner("127.0.0.1")
    await scan._prep()

    url = bbot_httpserver.url_for("/no_rate_limit_test")
    request_times = []
    for _ in range(num_requests):
        r = await scan.helpers.request(url)
        request_times.append(time.monotonic())
        assert r.status_code == 200

    elapsed = request_times[-1] - request_times[0]
    # without rate limiting, 20 requests to localhost should complete well under 2 seconds
    assert elapsed < 2.0, f"Requests unexpectedly slow without rate limiting: {elapsed:.2f}s"

    await scan._cleanup()
