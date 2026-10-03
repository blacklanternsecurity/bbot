import time
import asyncio

from ..bbot_fixtures import *  # noqa: F403

from bbot import __version__
from bbot.modules.base import BaseModule
from bbot.test.mock_blasthttp import MockResponse, TimeoutException


API_URL = "https://api.evilcorp.com/lookup?key={api_key}"


async def _make_module(scan, api_keys=None):
    class dummy_api(BaseModule):
        _name = "dummy_api"
        watched_events = ["DNS_NAME"]
        # keep backoff short so tests stay fast
        _api_retry_backoff = 0.05

    module = dummy_api(scan)
    if api_keys:
        module.api_key = api_keys
    return module


def _responder(blasthttp_mock, *statuses, headers=None):
    """Answer requests with the given statuses in order (the last one repeats), recording each request."""
    requests = []

    def callback(request):
        index = min(len(requests), len(statuses) - 1)
        requests.append((time.monotonic(), request))
        status = statuses[index]
        if status == "timeout":
            raise TimeoutException("timeout")
        return MockResponse(status_code=status, headers=headers or {})

    blasthttp_mock.add_callback(callback)
    return requests


async def test_api_request_rate_limits_are_not_failures(bbot_scanner, blasthttp_mock):
    scan = bbot_scanner(config={"web": {"429_sleep_interval": 0}})
    module = await _make_module(scan)
    requests = _responder(blasthttp_mock, 429)
    # more rate limits than the failure threshold, but fewer than the rate limit threshold
    for _ in range(3):
        await module.api_request(API_URL)
    assert len(requests) == 9
    assert module._api_request_failures == 0
    assert module._api_rate_limit_count == 9
    assert module.errored is False


async def test_api_request_persistent_rate_limit_errors(bbot_scanner, blasthttp_mock):
    scan = bbot_scanner(config={"web": {"429_sleep_interval": 0}})
    module = await _make_module(scan)
    requests = _responder(blasthttp_mock, 429)
    for _ in range(5):
        await module.api_request(API_URL)
    assert module.api_rate_limit_abort_threshold == 10
    assert len(requests) == 10
    assert module._api_request_failures == 0
    assert module.errored is True


async def test_api_request_rate_limit_threshold_scales_with_keys(bbot_scanner, blasthttp_mock):
    scan = bbot_scanner(config={"web": {"429_sleep_interval": 0}})
    module = await _make_module(scan, api_keys=["key1", "key2", "key3"])
    requests = _responder(blasthttp_mock, 429)
    for _ in range(20):
        await module.api_request(API_URL)
        if module.errored:
            break
    assert module.api_rate_limit_abort_threshold == 30
    assert len(requests) == 30
    assert module.errored is True


async def test_api_request_non_429_resets_rate_limit_count(bbot_scanner, blasthttp_mock):
    """Any response other than a 429 resets the rate limit count. A real failure counts as a failure."""
    scan = bbot_scanner(config={"web": {"429_sleep_interval": 0}})
    module = await _make_module(scan)

    _responder(blasthttp_mock, 429, 429, 200, 429, 429, 500)
    await module.api_request(API_URL)
    assert module._api_rate_limit_count == 0
    assert module._api_request_failures == 0

    await module.api_request(API_URL)
    assert module._api_rate_limit_count == 0
    assert module._api_request_failures == 1
    assert module.errored is False


async def test_api_request_cycles_key_on_429(bbot_scanner, blasthttp_mock):
    scan = bbot_scanner(config={"web": {"429_sleep_interval": 0}})
    module = await _make_module(scan, api_keys=["key1", "key2"])
    requests = _responder(blasthttp_mock, 429, 200)
    r = await module.api_request(API_URL)
    assert r.status_code == 200
    assert [str(req.url) for _, req in requests] == [
        "https://api.evilcorp.com/lookup?key=key1",
        "https://api.evilcorp.com/lookup?key=key2",
    ]
    assert module._api_rate_limit_count == 0


async def test_api_request_obeys_retry_after_across_handlers(bbot_scanner, blasthttp_mock):
    """A Retry-After received by one caller holds back every caller in the module."""
    scan = bbot_scanner()
    module = await _make_module(scan)
    requests = []

    def callback(request):
        requests.append(time.monotonic())
        if len(requests) == 1:
            return MockResponse(status_code=429, headers={"Retry-After": "1"})
        return MockResponse(status_code=200)

    blasthttp_mock.add_callback(callback)

    first = asyncio.create_task(module.api_request(API_URL))
    # let the first caller receive its 429 before the second one starts
    while not requests:
        await asyncio.sleep(0.01)
    await asyncio.sleep(0.05)
    second = asyncio.create_task(module.api_request(API_URL))
    await asyncio.gather(first, second)

    assert len(requests) == 3
    # both follow-up requests waited out the Retry-After
    assert all(t - requests[0] >= 1 for t in requests[1:])


async def test_api_request_backs_off_between_failures(bbot_scanner, blasthttp_mock):
    scan = bbot_scanner()
    module = await _make_module(scan)
    requests = _responder(blasthttp_mock, "timeout")
    await module.api_request(API_URL)
    times = [t for t, _ in requests]
    assert len(times) == 3
    assert times[1] - times[0] >= 0.05
    assert times[2] - times[1] >= 0.1
    assert module._api_request_failures == 3


async def test_api_request_404_is_not_a_failure(bbot_scanner, blasthttp_mock):
    scan = bbot_scanner()
    module = await _make_module(scan)
    requests = _responder(blasthttp_mock, 404)
    for _ in range(module.api_failure_abort_threshold + 5):
        await module.api_request(API_URL)
    assert len(requests) == module.api_failure_abort_threshold + 5
    assert module._api_request_failures == 0
    assert module.errored is False


async def test_api_request_ping_does_not_wait_on_429(bbot_scanner, blasthttp_mock):
    """With retry_on_http_429=False (setup pings), a 429 returns right away and isn't counted."""
    scan = bbot_scanner()
    module = await _make_module(scan)
    requests = _responder(blasthttp_mock, 429)
    start = time.monotonic()
    r = await module.api_request(API_URL, retry_on_http_429=False)
    assert time.monotonic() - start < 1
    assert r.status_code == 429
    assert len(requests) == 1
    assert module._api_rate_limit_count == 0
    assert module._api_rate_limited_until == 0


async def test_api_request_user_agent(bbot_scanner, blasthttp_mock):
    scan = bbot_scanner(config={"web": {"user_agent_suffix": "engagement-1234"}})
    module = await _make_module(scan)
    requests = _responder(blasthttp_mock, 200)
    await module.api_request(API_URL)
    await module.api_request(API_URL, headers={"User-Agent": "custom"})
    user_agents = [dict(req.headers).get("User-Agent") for _, req in requests]
    assert user_agents == [f"BBOT/{__version__}", "custom"]


async def test_api_request_retry_after_parsing(bbot_scanner):
    scan = bbot_scanner()
    module = await _make_module(scan)
    assert module._get_retry_after(MockResponse(status_code=429, headers={"Retry-After": "5"})) == 5
    assert module._get_retry_after(MockResponse(status_code=429, headers={"Retry-After": "1.5"})) == 1.5
    # a zero or negative Retry-After is raised to one second
    assert module._get_retry_after(MockResponse(status_code=429, headers={"Retry-After": "0"})) == 1
    # an HTTP date in the past is also raised to one second, rather than raising an error
    date = "Wed, 21 Oct 2015 07:28:00 GMT"
    assert module._get_retry_after(MockResponse(status_code=429, headers={"Retry-After": date})) == 1
    assert module._get_retry_after(MockResponse(status_code=429, headers={"Retry-After": "garbage"})) is None
    assert module._get_retry_after(MockResponse(status_code=429)) is None
