import httpx

from .base import ModuleTestBase


class TestRapidDNS(ModuleTestBase):
    web_body = """<th scope="row ">12</th>
<td>asdf.blacklanternsecurity.com</td>
<td><a href="/sameip/asdf.blacklanternsecurity.com.?t=cname#result" target="_blank" title="asdf.blacklanternsecurity.com. same ip website">asdf.blacklanternsecurity.com.</a>"""

    async def setup_after_prep(self, module_test):
        module_test.module.abort_if = lambda e: False
        module_test.httpx_mock.add_response(
            url="https://rapiddns.io/subdomain/blacklanternsecurity.com?full=1#result", text=self.web_body
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"


class TestRapidDNSAbortThreshold1(TestRapidDNS):
    module_name = "rapiddns"

    async def setup_after_prep(self, module_test):
        self.url_count = {}

        async def custom_callback(request):
            url = str(request.url)
            try:
                self.url_count[url] += 1
            except KeyError:
                self.url_count[url] = 1
            raise httpx.TimeoutException("timeout")

        module_test.httpx_mock.add_callback(custom_callback)

        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["127.0.0.88"]},
                "evilcorp.com": {"A": ["127.0.0.11"]},
                "evilcorp.net": {"A": ["127.0.0.22"]},
                "evilcorp.co.uk": {"A": ["127.0.0.33"]},
            }
        )

    def check(self, module_test, events):
        assert module_test.module.api_failure_abort_threshold == 10
        assert module_test.module.errored is False
        assert module_test.module._api_request_failures == 3
        assert module_test.module.api_retries == 3
        assert {e.data for e in events if e.type == "DNS_NAME"} == {"blacklanternsecurity.com"}
        assert self.url_count == {
            "https://rapiddns.io/subdomain/blacklanternsecurity.com?full=1#result": 3,
        }


class TestRapidDNSAbortThreshold2(TestRapidDNSAbortThreshold1):
    targets = ["blacklanternsecurity.com", "evilcorp.com"]

    def check(self, module_test, events):
        assert module_test.module.api_failure_abort_threshold == 10
        assert module_test.module.errored is False
        assert module_test.module._api_request_failures == 6
        assert module_test.module.api_retries == 3
        assert {e.data for e in events if e.type == "DNS_NAME"} == {"blacklanternsecurity.com", "evilcorp.com"}
        assert self.url_count == {
            "https://rapiddns.io/subdomain/blacklanternsecurity.com?full=1#result": 3,
            "https://rapiddns.io/subdomain/evilcorp.com?full=1#result": 3,
        }


class TestRapidDNSAbortThreshold3(TestRapidDNSAbortThreshold1):
    targets = ["blacklanternsecurity.com", "evilcorp.com", "evilcorp.net"]

    def check(self, module_test, events):
        assert module_test.module.api_failure_abort_threshold == 10
        assert module_test.module.errored is False
        assert module_test.module._api_request_failures == 9
        assert module_test.module.api_retries == 3
        assert {e.data for e in events if e.type == "DNS_NAME"} == {
            "blacklanternsecurity.com",
            "evilcorp.com",
            "evilcorp.net",
        }
        assert self.url_count == {
            "https://rapiddns.io/subdomain/blacklanternsecurity.com?full=1#result": 3,
            "https://rapiddns.io/subdomain/evilcorp.com?full=1#result": 3,
            "https://rapiddns.io/subdomain/evilcorp.net?full=1#result": 3,
        }


class TestRapidDNSAbortThreshold4(TestRapidDNSAbortThreshold1):
    targets = ["blacklanternsecurity.com", "evilcorp.com", "evilcorp.net", "evilcorp.co.uk"]

    def check(self, module_test, events):
        assert module_test.module.api_failure_abort_threshold == 10
        assert module_test.module.errored is True
        assert module_test.module._api_request_failures == 10
        assert module_test.module.api_retries == 3
        assert {e.data for e in events if e.type == "DNS_NAME"} == {
            "blacklanternsecurity.com",
            "evilcorp.com",
            "evilcorp.net",
            "evilcorp.co.uk",
        }
        assert len(self.url_count) == 4
        assert list(self.url_count.values()).count(3) == 3
        assert list(self.url_count.values()).count(1) == 1
