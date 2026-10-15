import json

from .base import ModuleTestBase

BASE_URL = "https://api.dnsdumpster.com/domain/blacklanternsecurity.com"


def page(hosts, total=None, txt=()):
    """A response page shaped like the live API's, with `total_a_recs` defaulting to this page's A records."""
    records = [{"host": h, "ips": [{"ip": "127.0.0.1"}]} for h in hosts]
    body = {
        "a": records,
        "cname": [],
        "mx": [{"host": "0 mail.blacklanternsecurity.com", "ips": []}],
        "ns": [],
        "txt": list(txt),
        "total_a_recs": len(records) if total is None else total,
    }
    return json.dumps(body).encode()


class TestDNSDumpster(ModuleTestBase):
    """Pages are requested until every A record in `total_a_recs` has been seen."""

    config_overrides = {"modules": {"dnsdumpster": {"api_key": "asdf"}}}

    async def setup_after_prep(self, module_test):
        module_test.blasthttp_mock.add_response(url=BASE_URL, content=page(["asdf.blacklanternsecurity.com"], total=2))
        module_test.blasthttp_mock.add_response(
            url=f"{BASE_URL}?page=2", content=page(["qwerty.blacklanternsecurity.com"], total=2)
        )
        module_test.blasthttp_mock.add_response(
            url=f"{BASE_URL}?page=3", content=page(["unrequested.blacklanternsecurity.com"], total=2)
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "qwerty.blacklanternsecurity.com" for e in events), "Failed to paginate"
        assert not any(e.data == "unrequested.blacklanternsecurity.com" for e in events), "Paged past the total"


class TestDNSDumpsterSinglePage(ModuleTestBase):
    """A first page holding every A record must not trigger a second request. Hostnames outside the host fields are kept."""

    modules_overrides = ["dnsdumpster"]
    config_overrides = {"modules": {"dnsdumpster": {"api_key": "asdf"}}}

    async def setup_after_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url=BASE_URL,
            content=page(["asdf.blacklanternsecurity.com"], txt=["v=spf1 include:spf.blacklanternsecurity.com ~all"]),
        )
        module_test.blasthttp_mock.add_response(
            url=f"{BASE_URL}?page=2", content=page(["unrequested.blacklanternsecurity.com"])
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "spf.blacklanternsecurity.com" for e in events), "Failed to extract hostname from TXT"
        assert any(e.data == "mail.blacklanternsecurity.com" for e in events), "Failed to extract MX host"
        assert not any(e.data == "unrequested.blacklanternsecurity.com" for e in events), "Requested a second page"


class TestDNSDumpsterNoTotal(ModuleTestBase):
    """Without `total_a_recs` there is no way to know more pages exist, so only the first is requested."""

    modules_overrides = ["dnsdumpster"]
    config_overrides = {"modules": {"dnsdumpster": {"api_key": "asdf"}}}

    async def setup_after_prep(self, module_test):
        body = json.loads(page(["asdf.blacklanternsecurity.com"]))
        del body["total_a_recs"]
        module_test.blasthttp_mock.add_response(url=BASE_URL, content=json.dumps(body).encode())
        module_test.blasthttp_mock.add_response(
            url=f"{BASE_URL}?page=2", content=page(["unrequested.blacklanternsecurity.com"])
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert not any(e.data == "unrequested.blacklanternsecurity.com" for e in events), "Requested a second page"


class TestDNSDumpsterFreeTier(ModuleTestBase):
    """A free key gets 401 when it asks for page 2; results so far are still kept."""

    modules_overrides = ["dnsdumpster"]
    config_overrides = {"modules": {"dnsdumpster": {"api_key": "asdf"}}}

    async def setup_after_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url=BASE_URL, content=page(["asdf.blacklanternsecurity.com"], total=200)
        )
        module_test.blasthttp_mock.add_response(
            url=f"{BASE_URL}?page=2",
            status_code=401,
            content=b'{"error":"pagination requires plus or max membership"}',
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
