import urllib.parse

from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_URL


class TestSpeculate_Subdirectories(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/subdir1/subdir2/"]
    modules_overrides = ["http", "speculate"]

    async def setup_before_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/subdir1/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/subdir1/subdir2/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.type == "URL_UNVERIFIED" and e.url == f"{HTTPSERVER_URL}/subdir1/" for e in events)


class TestSpeculate_OpenPorts(ModuleTestBase):
    targets = ["evilcorp.com"]
    modules_overrides = ["speculate", "certspotter", "shodan_idb"]
    config_overrides = {"speculate": True}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "evilcorp.com": {"A": ["127.0.254.1"]},
                "asdf.evilcorp.com": {"A": ["127.0.254.2"]},
            }
        )

        module_test.blasthttp_mock.add_response(
            url="https://api.certspotter.com/v1/issuances?domain=evilcorp.com&include_subdomains=true&expand=dns_names",
            json=[{"dns_names": ["*.asdf.evilcorp.com"]}],
        )

        from bbot.modules.base import BaseModule

        class DummyModule(BaseModule):
            _name = "dummy"
            watched_events = ["OPEN_TCP_PORT"]
            scope_distance_modifier = 10
            accept_dupes = True

            async def setup(self):
                self.events = []
                return True

            async def handle_event(self, event):
                self.events.append(event)

        dummy_module = DummyModule(module_test.scan)
        await dummy_module.setup()
        module_test.scan.modules["dummy"] = dummy_module

        # Manually configure speculate module to emit OPEN_TCP_PORT events
        # since the dummy module was added after speculate's setup phase
        speculate_module = module_test.scan.modules["speculate"]
        speculate_module.open_port_consumers = True
        speculate_module._always_emit_open_ports = True

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://api.certspotter.com/v1/issuances?domain=evilcorp.com&include_subdomains=true&expand=dns_names",
            json=[{"dns_names": ["*.asdf.evilcorp.com"]}],
        )

    def check(self, module_test, events):
        events_data = set()
        for e in module_test.scan.modules["dummy"].events:
            events_data.add(e.data)
        assert all(
            x in events_data
            for x in ("evilcorp.com:80", "evilcorp.com:443", "asdf.evilcorp.com:80", "asdf.evilcorp.com:443")
        )


class TestSpeculate_OutOfScopeIPRange(ModuleTestBase):
    """Out-of-scope IP ranges from SPF (or any source) should not be enumerated into individual IPs."""

    targets = ["evilcorp.com"]
    modules_overrides = ["speculate"]
    config_overrides = {"dns": {"minimal": False}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "evilcorp.com": {
                    "A": ["127.0.254.1"],
                    "TXT": ['"v=spf1 ip4:192.168.0.0/24 ~all"'],
                },
            }
        )

        from bbot.modules.base import BaseModule

        class IPCollector(BaseModule):
            _name = "ip_collector"
            watched_events = ["IP_ADDRESS"]
            scope_distance_modifier = 10
            accept_dupes = True

            async def setup(self):
                self.events = []
                return True

            async def handle_event(self, event):
                self.events.append(event)

        collector = IPCollector(module_test.scan)
        await collector.setup()
        module_test.scan.modules["ip_collector"] = collector

    def check(self, module_test, events):
        import ipaddress

        net = ipaddress.ip_network("192.168.0.0/24")
        speculated_ips = [
            e
            for e in module_test.scan.modules["ip_collector"].events
            if e.type == "IP_ADDRESS" and ipaddress.ip_address(e.data) in net
        ]
        assert len(speculated_ips) == 0, (
            f"speculate enumerated {len(speculated_ips)} IPs from out-of-scope IP_RANGE 192.168.0.0/24"
        )


class TestSpeculate_OpenPorts_Portscanner(TestSpeculate_OpenPorts):
    targets = ["evilcorp.com"]
    modules_overrides = ["speculate", "certspotter", "portscan"]
    config_overrides = {"speculate": True}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "evilcorp.com": {"A": ["127.0.254.1"]},
                "asdf.evilcorp.com": {"A": ["127.0.254.2"]},
            }
        )

        from bbot.modules.base import BaseModule

        class DummyModule(BaseModule):
            _name = "dummy"
            watched_events = ["OPEN_TCP_PORT"]
            scope_distance_modifier = 10
            accept_dupes = True

            async def setup(self):
                self.events = []
                return True

            async def handle_event(self, event):
                self.events.append(event)

        dummy_module = DummyModule(module_test.scan)
        await dummy_module.setup()
        module_test.scan.modules["dummy"] = dummy_module

        # DON'T manually configure speculate module here - we want it to detect
        # the portscan module and NOT emit OPEN_TCP_PORT events

    def check(self, module_test, events):
        events_data = set()
        for e in module_test.scan.modules["dummy"].events:
            events_data.add(e.data)
        assert not any(
            x in events_data
            for x in ("evilcorp.com:80", "evilcorp.com:443", "asdf.evilcorp.com:80", "asdf.evilcorp.com:443")
        )


def quoted(url):
    return urllib.parse.quote(url, safe="")


class TestSpeculate_ParameterUrls(ModuleTestBase):
    """
    A URL in the query string of a URL the scan visits, like an OAuth redirect_uri or a login's return URL, is followed
    like a redirect: without spider-danger, so the spider's limits don't stop it, and through URLs nested in each other's
    parameters. Pages that differ only in that parameter each get theirs followed, whatever their content
    """

    callback = f"{HTTPSERVER_URL}/a/b/c/d/callback.html?clientId=app&fromUrl={quoted(HTTPSERVER_URL + '/home')}"
    targets = [
        f"{HTTPSERVER_URL}/authorize?client_id=app&redirect_uri={quoted(callback)}&state=xyz"
        f"&return={quoted('https://outofscope.example/x')}",
        f"{HTTPSERVER_URL}/login?next={quoted(HTTPSERVER_URL + '/dash')}",
        f"{HTTPSERVER_URL}/login?next={quoted(HTTPSERVER_URL + '/settings')}",
    ]
    modules_overrides = ["http", "speculate"]
    config_overrides = {"url_querystring_remove": False, "url_querystring_collapse": False}

    async def setup_after_prep(self, module_test):
        # as an authorization server does, the authorize endpoint sends the browser on to a sign-in page of its own
        module_test.set_expect_requests(
            {"uri": "/authorize"},
            {"response_data": "", "status": 302, "headers": {"Location": "/signin?oauth_state=s"}},
        )
        # one page, whatever URL it's at
        for uri in ("/signin", "/a/b/c/d/callback.html", "/home", "/login", "/dash", "/settings"):
            module_test.set_expect_requests({"uri": uri}, {"response_data": "<html>the same page</html>"})

    def check(self, module_test, events):
        urls = {e.url: e for e in events if e.type == "URL"}
        callbacks = [e for url, e in urls.items() if "/a/b/c/d/callback.html?" in url]
        assert callbacks, f"the redirect_uri wasn't visited: {sorted(urls)}"
        assert "spider-danger" not in callbacks[0].tags
        # the URL in the callback's own query string
        assert f"{HTTPSERVER_URL}/home" in urls, f"the URL in the callback's parameters wasn't visited: {sorted(urls)}"
        # both return URLs, though the pages they were found in are the same page
        assert f"{HTTPSERVER_URL}/dash" in urls and f"{HTTPSERVER_URL}/settings" in urls, sorted(urls)
        # not the scan's to visit
        assert not any(urllib.parse.urlparse(url).hostname == "outofscope.example" for url in urls)


class TestSpeculate_ParameterUrlsQuerystringRemoved(TestSpeculate_ParameterUrls):
    """With the query string removed from the URLs the scan visits, there's none to find URLs in"""

    config_overrides = {"url_querystring_remove": True}

    def check(self, module_test, events):
        urls = {e.url for e in events if e.type == "URL"}
        followed = [url for url in urls if "callback.html" in url or url.endswith(("/home", "/dash", "/settings"))]
        assert not followed, sorted(urls)
