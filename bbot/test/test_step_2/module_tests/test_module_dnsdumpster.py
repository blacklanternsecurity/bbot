import json

from .base import ModuleTestBase


def page(hosts, pad_to=0, txt=()):
    """A response page. `pad_to` inflates the record count so the module keeps paging."""
    records = [{"host": h, "ips": []} for h in hosts]
    records += [{"host": f"filler{i}.example.com", "ips": []} for i in range(pad_to - len(records))]
    return json.dumps({"a": records, "cname": [], "mx": [], "ns": [], "txt": list(txt)}).encode()


class TestDNSDumpster(ModuleTestBase):
    config_overrides = {"modules": {"dnsdumpster": {"api_key": "asdf"}}}

    async def setup_after_prep(self, module_test):
        # a full first page forces a second request; the short second page ends it
        module_test.blasthttp_mock.add_response(
            url="https://api.dnsdumpster.com/domain/blacklanternsecurity.com",
            content=page(["asdf.blacklanternsecurity.com"], pad_to=200),
        )
        module_test.blasthttp_mock.add_response(
            url="https://api.dnsdumpster.com/domain/blacklanternsecurity.com?page=2",
            content=page(["qwerty.blacklanternsecurity.com"]),
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "qwerty.blacklanternsecurity.com" for e in events), "Failed to paginate"


class TestDNSDumpsterSinglePage(ModuleTestBase):
    """A short first page must not trigger a second request. Hostnames outside the host fields are kept."""

    modules_overrides = ["dnsdumpster"]
    config_overrides = {"modules": {"dnsdumpster": {"api_key": "asdf"}}}

    async def setup_after_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://api.dnsdumpster.com/domain/blacklanternsecurity.com",
            content=page(["asdf.blacklanternsecurity.com"], txt=["v=spf1 include:spf.blacklanternsecurity.com ~all"]),
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "spf.blacklanternsecurity.com" for e in events), "Failed to extract hostname from TXT"


class TestDNSDumpsterFreeTier(ModuleTestBase):
    """A free key gets 403 when it asks for page 2; results so far are still kept."""

    modules_overrides = ["dnsdumpster"]
    config_overrides = {"modules": {"dnsdumpster": {"api_key": "asdf"}}}

    async def setup_after_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://api.dnsdumpster.com/domain/blacklanternsecurity.com",
            content=page(["asdf.blacklanternsecurity.com"], pad_to=200),
        )
        module_test.blasthttp_mock.add_response(
            url="https://api.dnsdumpster.com/domain/blacklanternsecurity.com?page=2",
            status_code=403,
            content=b'{"error": "Plus membership required"}',
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
