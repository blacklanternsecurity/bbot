from .base import ModuleTestBase, tempwordlist
import re
from werkzeug.wrappers import Response


class VirtualhostTestBase(ModuleTestBase):
    """Base class for virtualhost tests with common setup"""

    async def setup_before_prep(self, module_test):
        # Fix randomness for predictable canary generation
        module_test.monkeypatch.setattr("random.seed", lambda x: None)
        import string

        def predictable_choice(seq):
            return seq[0] if seq == string.ascii_lowercase else seq[0]

        module_test.monkeypatch.setattr("random.choice", predictable_choice)

    async def setup_after_prep(self, module_test):
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)


class TestVirtualhostSpecialHosts(VirtualhostTestBase):
    """Test special hosts detection"""

    targets = ["http://localhost:8888"]
    modules_overrides = ["http", "virtualhost"]
    config_overrides = {
        "modules": {
            "virtualhost": {
                "subdomain_brute": False,  # Focus on special hosts only
                "mutation_check": False,  # Focus on special hosts only
                "special_hosts": True,  # Enable special hosts
                "certificate_sans": False,
                "wordcloud_check": False,
                "require_inaccessible": False,
            }
        }
    }

    async def setup_after_prep(self, module_test):
        # Keep request handler-based HTTP server
        await super().setup_after_prep(module_test)

        # Emit URL event manually and ensure resolved_hosts
        from bbot.modules.base import BaseModule

        class DummyModule(BaseModule):
            _name = "dummy_module_special"
            watched_events = ["SCAN"]

            async def handle_event(self, event):
                if event.type == "SCAN":
                    url_event = self.scan.make_event(
                        "http://localhost:8888/",
                        "URL",
                        parent=event,
                        tags=["status-200", "ip-127.0.0.1"],
                    )
                    await self.emit_event(url_event)

        module_test.scan.modules["dummy_module_special"] = DummyModule(module_test.scan)

        # Patch virtualhost to inject resolved_hosts
        vh_module = module_test.scan.modules["virtualhost"]
        orig_handle_event = vh_module.handle_event

        async def patched_handle_event(ev):
            ev._resolved_hosts = {"127.0.0.1"}
            return await orig_handle_event(ev)

        module_test.monkeypatch.setattr(vh_module, "handle_event", patched_handle_event)

    def request_handler(self, request):
        host_header = request.headers.get("Host", "").lower()

        # Baseline request to localhost (with or without port)
        if not host_header or host_header in ["localhost", "localhost:8888"]:
            return Response("baseline response from localhost", status=200)

        # Wildcard canary check
        if re.match(r"[a-z]ocalhost(?::8888)?$", host_header):
            return Response("different wildcard response", status=404)

        # Random canary requests (12 lowercase letters .com)
        if re.match(r"^[a-z]{12}\.com(?::8888)?$", host_header):
            return Response(
                """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>Random canary host.</p></body></html>""",
                status=404,
            )

        # Special hosts responses - return different content than canary
        if host_header == "host.docker.internal":
            return Response("Docker internal host active", status=200)
        if host_header == "127.0.0.1":
            return Response("Loopback host active", status=200)
        if host_header == "localhost":
            return Response("Localhost virtual host active", status=200)

        # Default for any other requests - match canary content to avoid false positives
        return Response(
            """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>Random canary host.</p></body></html>""",
            status=404,
        )

    def check(self, module_test, events):
        special_hosts_found = set()
        for e in events:
            if e.type == "VIRTUAL_HOST":
                vhost = e.data["virtual_host"]
                if vhost in ["host.docker.internal", "127.0.0.1", "localhost"]:
                    special_hosts_found.add(vhost)

                    # Test description elements to ensure they are as expected
                    description = e.data["description"]
                    assert (
                        "Discovery Technique: [Special virtual host list" in description
                        or "Discovery Technique: [Mutations on discovered" in description
                    ), f"Description missing or unexpected discovery technique: {description}"
                    assert "Status Code:" in description, f"Description missing status code: {description}"
                    assert "Size:" in description and "bytes" in description, (
                        f"Description missing size: {description}"
                    )
                    assert "IP: 127.0.0.1" in description, f"Description missing IP: {description}"
                    assert "Access:" in description, f"Description missing access status: {description}"

        assert len(special_hosts_found) >= 1, f"Failed to detect special virtual hosts. Found: {special_hosts_found}"


class TestVirtualhostBruteForce(VirtualhostTestBase):
    """Test subdomain brute-force detection using HTTP Host headers"""

    targets = ["http://test.example:8888"]
    modules_overrides = ["virtualhost"]  # Remove http, we'll manually create URL events
    test_wordlist = ["admin", "api", "test"]
    config_overrides = {
        "modules": {
            "virtualhost": {
                "brute_wordlist": tempwordlist(test_wordlist),
                "subdomain_brute": True,  # Enable brute force
                "mutation_check": False,  # Focus on brute force only
                "special_hosts": False,  # Focus on brute force only
                "certificate_sans": False,
                "wordcloud_check": False,
                "require_inaccessible": False,
            }
        }
    }

    async def setup_after_prep(self, module_test):
        # Call parent setup_after_prep to set up the HTTP server with request_handler
        await super().setup_after_prep(module_test)

        # Set up DNS mocking for test.example to resolve to 127.0.0.1
        await module_test.mock_dns({"test.example": {"A": ["127.0.0.1"]}})

        # Create a dummy module that will emit the URL event during the scan
        from bbot.modules.base import BaseModule

        class DummyModule(BaseModule):
            _name = "dummy_module"
            watched_events = ["SCAN"]

            async def handle_event(self, event):
                if event.type == "SCAN":
                    # Create and emit URL event for virtualhost module to process
                    url_event = self.scan.make_event(
                        "http://test.example:8888/", "URL", parent=event, tags=["status-200", "ip-127.0.0.1"]
                    )
                    await self.emit_event(url_event)

        # Add the dummy module to the scan
        dummy_module = DummyModule(module_test.scan)
        module_test.scan.modules["dummy_module"] = dummy_module

        # Patch virtualhost to inject resolved_hosts for URL events during the test
        vh_module = module_test.scan.modules["virtualhost"]
        orig_handle_event = vh_module.handle_event

        async def patched_handle_event(ev):
            ev._resolved_hosts = {"127.0.0.1"}
            return await orig_handle_event(ev)

        module_test.monkeypatch.setattr(vh_module, "handle_event", patched_handle_event)

    def request_handler(self, request):
        from werkzeug.wrappers import Response

        host_header = request.headers.get("Host", "").lower()

        # Baseline request to test.example or example (with or without port)
        if not host_header or host_header in ["test.example", "test.example:8888", "example", "example:8888"]:
            return Response("baseline response from example baseline", status=200)

        # Wildcard canary check - change one character in test.example
        if re.match(r"[a-z]est\.example", host_header):
            return Response("wildcard canary different response", status=404)

        # Brute-force canary requests - random string + .test.example (with optional port)
        if re.match(r"^[a-z]{12}\.test\.example(?::8888)?$", host_header):
            return Response("subdomain canary response", status=404)

        # Brute-force matches on discovered basehost (admin|api|test).test.example (with optional port)
        if host_header in ["admin.test.example", "admin.test.example:8888"]:
            return Response("Admin panel found here!", status=200)
        if host_header in ["api.test.example", "api.test.example:8888"]:
            return Response("API endpoint found here!", status=200)
        if host_header in ["test.test.example", "test.test.example:8888"]:
            return Response("Test environment found here!", status=200)

        # Default response
        return Response("default response", status=404)

    def check(self, module_test, events):
        brute_hosts_found = set()
        for e in events:
            if e.type == "VIRTUAL_HOST":
                vhost = e.data["virtual_host"]
                if vhost in ["admin.test.example", "api.test.example", "test.test.example"]:
                    brute_hosts_found.add(vhost)

        assert len(brute_hosts_found) >= 1, f"Failed to detect brute-force virtual hosts. Found: {brute_hosts_found}"


class TestVirtualhostMutations(VirtualhostTestBase):
    """Test host mutation detection using HTTP Host headers"""

    targets = ["http://subdomain.target.test:8888"]
    modules_overrides = ["http", "virtualhost"]
    config_overrides = {
        "modules": {
            "virtualhost": {
                "subdomain_brute": False,  # Focus on mutations only
                "mutation_check": True,  # Enable mutations
                "special_hosts": False,  # Focus on mutations only
                "certificate_sans": False,
                "wordcloud_check": False,
                "require_inaccessible": False,
            }
        }
    }

    async def setup_before_prep(self, module_test):
        # Call parent setup first
        await super().setup_before_prep(module_test)

        # Mock wordcloud.mutations to return predictable results for "target"
        def mock_mutations(self, word, **kwargs):
            # Return realistic mutations that would be found for "target"
            return [
                [word, "dev"],  # targetdev, target-dev
                ["dev", word],  # devtarget, dev-target
                [word, "test"],  # targettest, target-test
            ]

        module_test.monkeypatch.setattr("bbot.core.helpers.wordcloud.WordCloud.mutations", mock_mutations)

    async def setup_after_prep(self, module_test):
        # Keep request handler-based HTTP server
        await super().setup_after_prep(module_test)

        # Set up DNS mocking for target.test
        await module_test.mock_dns({"target.test": {"A": ["127.0.0.1"]}})

        # Emit URL event manually and ensure resolved_hosts
        from bbot.modules.base import BaseModule

        class DummyModule(BaseModule):
            _name = "dummy_module_mut"
            watched_events = ["SCAN"]

            async def handle_event(self, event):
                if event.type == "SCAN":
                    url_event = self.scan.make_event(
                        "http://subdomain.target.test:8888/",
                        "URL",
                        parent=event,
                        tags=["status-200", "ip-127.0.0.1"],
                    )
                    await self.emit_event(url_event)

        module_test.scan.modules["dummy_module_mut"] = DummyModule(module_test.scan)

        # Patch virtualhost to inject resolved hosts
        vh_module = module_test.scan.modules["virtualhost"]
        orig_handle_event = vh_module.handle_event

        async def patched_handle_event(ev):
            ev._resolved_hosts = {"127.0.0.1"}
            return await orig_handle_event(ev)

        module_test.monkeypatch.setattr(vh_module, "handle_event", patched_handle_event)

    def request_handler(self, request):
        host_header = request.headers.get("Host", "").lower()

        # Baseline request to target.test (with or without port)
        if not host_header or host_header in ["subdomain.target.test", "subdomain.target.test:8888"]:
            return Response("baseline response from target.test", status=200)

        # Wildcard canary check
        if re.match(r"[a-z]subdomain\.target\.test(?::8888)?$", host_header):  # Modified target.test
            return Response("wildcard canary response", status=404)

        # Mutation canary requests (4 chars + dash + original host)
        if re.match(r"^[a-z]{4}-subdomain\.target\.test(?::8888)?$", host_header):
            return Response("<!DOCTYPE html><html><body>Mutation Canary</body></html>", status=404)

        # Word cloud mutation matches - return different content than canary
        if host_header == "subdomain-dev.target.test":
            return Response("Dev target 1 found!", status=200)
        if host_header == "devsubdomain.target.test":
            return Response("Dev target 2 found!", status=200)
        if host_header == "subdomaintest.target.test":
            return Response("Test target found!", status=200)

        # Default response
        return Response(
            """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>Default handler response.</p></body></html>""",
            status=404,
        )

    def check(self, module_test, events):
        mutation_hosts_found = set()
        for e in events:
            if e.type == "VIRTUAL_HOST":
                vhost = e.data["virtual_host"]
                # Look for mutation patterns with dev/test
                if any(word in vhost for word in ["dev", "test"]) and "target" in vhost:
                    mutation_hosts_found.add(vhost)

        assert len(mutation_hosts_found) >= 1, (
            f"Failed to detect mutation virtual hosts. Found: {mutation_hosts_found}"
        )


class TestVirtualhostWordcloud(VirtualhostTestBase):
    """Test finish() wordcloud-based detection using HTTP Host headers"""

    targets = ["http://wordcloud.test:8888"]
    modules_overrides = ["http", "virtualhost"]
    config_overrides = {
        "modules": {
            "virtualhost": {
                "subdomain_brute": False,  # Focus on wordcloud only
                "mutation_check": False,  # Focus on wordcloud only
                "special_hosts": False,  # Focus on wordcloud only
                "certificate_sans": False,
                "wordcloud_check": True,  # Enable wordcloud
                "require_inaccessible": False,
            }
        }
    }

    async def setup_after_prep(self, module_test):
        # Keep request handler-based HTTP server
        await super().setup_after_prep(module_test)

        # Set up DNS mocking for wordcloud.test
        await module_test.mock_dns({"wordcloud.test": {"A": ["127.0.0.1"]}})

        # Mock wordcloud to have some common words
        def mock_wordcloud_keys(self):
            return ["staging", "prod", "dev", "admin", "api"]

        module_test.monkeypatch.setattr("bbot.core.helpers.wordcloud.WordCloud.keys", mock_wordcloud_keys)

        # Emit URL event manually and ensure resolved_hosts
        from bbot.modules.base import BaseModule

        class DummyModule(BaseModule):
            _name = "dummy_module_wc"
            watched_events = ["SCAN"]

            async def handle_event(self, event):
                if event.type == "SCAN":
                    url_event = self.scan.make_event(
                        "http://wordcloud.test:8888/",
                        "URL",
                        parent=event,
                        tags=["status-200", "ip-127.0.0.1"],
                    )
                    await self.emit_event(url_event)

        module_test.scan.modules["dummy_module_wc"] = DummyModule(module_test.scan)

        # Patch virtualhost to inject resolved hosts
        vh_module = module_test.scan.modules["virtualhost"]
        orig_handle_event = vh_module.handle_event

        async def patched_handle_event(ev):
            ev._resolved_hosts = {"127.0.0.1"}
            return await orig_handle_event(ev)

        module_test.monkeypatch.setattr(vh_module, "handle_event", patched_handle_event)

    def request_handler(self, request):
        host_header = request.headers.get("Host", "").lower()

        # Baseline request to wordcloud.test (with or without port)
        if not host_header or host_header in ["wordcloud.test", "wordcloud.test:8888"]:
            return Response("baseline response from wordcloud.test", status=200)

        # Wildcard canary check
        if re.match(r"[a-z]ordcloud\.test(?::8888)?$", host_header):  # Modified wordcloud.test
            return Response("wildcard canary response", status=404)

        # Random canary requests (12 chars + .com)
        if re.match(r"^[a-z]{12}\.com(?::8888)?$", host_header):
            return Response("random canary response", status=404)

        # Wordcloud-based matches - these are checked in finish()
        if host_header in ["staging.wordcloud.test", "staging.wordcloud.test:8888"]:
            return Response("Staging environment found!", status=200)
        if host_header in ["prod.wordcloud.test", "prod.wordcloud.test:8888"]:
            return Response("Production environment found!", status=200)
        if host_header in ["dev.wordcloud.test", "dev.wordcloud.test:8888"]:
            return Response("Development environment found!", status=200)

        # Default response
        return Response("default response", status=404)

    def check(self, module_test, events):
        wordcloud_hosts_found = set()
        for e in events:
            if e.type == "VIRTUAL_HOST":
                vhost = e.data["virtual_host"]
                if vhost in ["staging.wordcloud.test", "prod.wordcloud.test", "dev.wordcloud.test"]:
                    wordcloud_hosts_found.add(vhost)

        assert len(wordcloud_hosts_found) >= 1, (
            f"Failed to detect wordcloud virtual hosts. Found: {wordcloud_hosts_found}"
        )


class TestVirtualhostHTTPSLogic(ModuleTestBase):
    """Unit tests for HTTPS/SNI-specific functions"""

    targets = ["http://localhost:8888"]  # Minimal target for unit testing
    modules_overrides = ["http", "virtualhost"]

    async def setup_before_prep(self, module_test):
        pass  # No special setup needed

    async def setup_after_prep(self, module_test):
        pass  # No HTTP mocking needed for unit tests

    def check(self, module_test, events):
        # Get the virtualhost module instance for direct testing
        virtualhost_module = None
        for module in module_test.scan.modules.values():
            if hasattr(module, "special_virtualhost_list"):
                virtualhost_module = module
                break

        assert virtualhost_module is not None, "Could not find virtualhost module instance"

        # Test canary host generation for different modes
        canary_subdomain = virtualhost_module._get_canary_random_host("test.example.com", ".example.com", "subdomain")
        canary_mutation = virtualhost_module._get_canary_random_host("test.example.com", ".example.com", "mutation")
        canary_random = virtualhost_module._get_canary_random_host("test.example.com", ".example.com", "random")

        # Verify canary patterns
        assert canary_subdomain.endswith(".example.com"), (
            f"Subdomain canary doesn't end with basehost: {canary_subdomain}"
        )
        assert "-test.example.com" in canary_mutation, (
            f"Mutation canary doesn't contain expected pattern: {canary_mutation}"
        )
        assert canary_random.endswith(".com"), f"Random canary doesn't end with .com: {canary_random}"

        # Test that all canaries are different
        assert canary_subdomain != canary_mutation != canary_random, "Canaries should be different"


class TestVirtualhostForceBasehost(VirtualhostTestBase):
    """Test force_basehost functionality specifically"""

    targets = ["http://127.0.0.1:8888"]  # Use IP to require force_basehost
    modules_overrides = ["http", "virtualhost"]
    test_wordlist = ["admin", "api"]
    config_overrides = {
        "modules": {
            "virtualhost": {
                "brute_wordlist": tempwordlist(test_wordlist),
                "force_basehost": "forced.domain",  # Test force_basehost functionality
                "subdomain_brute": True,
                "mutation_check": False,
                "special_hosts": False,
                "certificate_sans": False,
                "wordcloud_check": False,
                "require_inaccessible": False,
            }
        }
    }

    def request_handler(self, request):
        host_header = request.headers.get("Host", "").lower()

        # Baseline request to the IP
        if not host_header or host_header == "127.0.0.1:8888":
            return Response("baseline response from IP", status=200)

        # Wildcard canary check
        if re.match(r"[0-9]27\.0\.0\.1:8888", host_header):
            return Response("wildcard canary response", status=404)

        # Subdomain canary (12 random chars + .forced.domain)
        if re.match(r"[a-z]{12}\.forced\.domain", host_header):
            return Response("forced domain canary response", status=404)

        # Virtual hosts using forced basehost
        if host_header == "admin.forced.domain":
            return Response("Admin with forced basehost found!", status=200)
        if host_header == "api.forced.domain":
            return Response("API with forced basehost found!", status=200)

        # Default response
        return Response("default response", status=404)

    def check(self, module_test, events):
        forced_hosts_found = set()
        for e in events:
            if e.type == "VIRTUAL_HOST":
                vhost = e.data["virtual_host"]
                if vhost in ["admin.forced.domain", "api.forced.domain"]:
                    forced_hosts_found.add(vhost)

                    # Verify the description shows it used the forced basehost
                    description = e.data["description"]
                    assert "Subdomain Brute-force" in description, (
                        f"Expected subdomain brute-force discovery: {description}"
                    )

        assert len(forced_hosts_found) >= 1, (
            f"Failed to detect virtual hosts with force_basehost. Found: {forced_hosts_found}. "
            f"Expected at least one of: admin.forced.domain, api.forced.domain"
        )


class TestVirtualhostInterestingDefaultContent(VirtualhostTestBase):
    """Test reporting of interesting default canary content during wildcard check"""

    targets = ["http://interesting.test:8888"]
    modules_overrides = ["http", "virtualhost"]
    config_overrides = {
        "modules": {
            "virtualhost": {
                "subdomain_brute": False,
                "mutation_check": False,
                "special_hosts": False,
                "certificate_sans": False,
                "wordcloud_check": False,
                "report_interesting_default_content": True,
                "require_inaccessible": False,
            }
        }
    }

    async def setup_after_prep(self, module_test):
        # Start HTTP server
        await super().setup_after_prep(module_test)

        # Mock DNS resolution for interesting.test
        await module_test.mock_dns({"interesting.test": {"A": ["127.0.0.1"]}})

        # Dummy module to emit the URL event for the virtualhost module
        from bbot.modules.base import BaseModule

        class DummyModule(BaseModule):
            _name = "dummy_module_interesting"
            watched_events = ["SCAN"]

            async def handle_event(self, event):
                if event.type == "SCAN":
                    url_event = self.scan.make_event(
                        "http://interesting.test:8888/",
                        "URL",
                        parent=event,
                        tags=["status-404", "ip-127.0.0.1"],
                    )
                    await self.emit_event(url_event)

        module_test.scan.modules["dummy_module_interesting"] = DummyModule(module_test.scan)

        # Patch virtualhost to inject resolved hosts
        vh_module = module_test.scan.modules["virtualhost"]
        orig_handle_event = vh_module.handle_event

        async def patched_handle_event(ev):
            ev._resolved_hosts = {"127.0.0.1"}
            return await orig_handle_event(ev)

        module_test.monkeypatch.setattr(vh_module, "handle_event", patched_handle_event)

    def request_handler(self, request):
        host_header = request.headers.get("Host", "").lower()

        # Baseline response for original host (ensure status differs from canary)
        if not host_header or host_header in ["interesting.test", "interesting.test:8888"]:
            return Response("baseline not found", status=404)

        # Wildcard canary mutated hostname: change first alpha to 'z' -> znteresting.test
        if host_header in ["znteresting.test", "znteresting.test:8888"]:
            long_body = (
                "This is a sufficiently long default page body that exceeds forty characters "
                "to trigger the interesting default content branch."
            )
            return Response(long_body, status=200)

        # Default
        return Response("default response", status=404)

    def check(self, module_test, events):
        found_interesting = False
        found_correct_host = False
        for e in events:
            if e.type == "VIRTUAL_HOST":
                desc = e.data.get("description", "")
                if "Interesting Default Content (from intentionally-incorrect canary host)" in desc:
                    found_interesting = True
                    # The VIRTUAL_HOST should be the canary hostname used in the wildcard request
                    if e.data.get("virtual_host") == "znteresting.test":
                        found_correct_host = True
                    break

        assert found_interesting, "Expected VIRTUAL_HOST from interesting default canary content was not emitted"
        assert found_correct_host, "virtual_host should equal the canary hostname 'znteresting.test'"


class TestVirtualhostKeywordWildcard(VirtualhostTestBase):
    """Test keyword-based wildcard detection using 'www' in hostname"""

    targets = ["http://acme.test:8888"]
    modules_overrides = ["http", "virtualhost"]
    config_overrides = {
        "modules": {
            "virtualhost": {
                "subdomain_brute": True,
                "mutation_check": False,
                "special_hosts": False,
                "certificate_sans": False,
                "wordcloud_check": False,
                "require_inaccessible": False,
                # Keep brute_lines small and supply a tiny wordlist containing a 'www' entry and an exact match
            }
        }
    }

    async def setup_after_prep(self, module_test):
        # Start HTTP server with wildcard behavior for any hostname containing 'www'
        await super().setup_after_prep(module_test)

        # Mock DNS resolution for acme.test
        await module_test.mock_dns({"acme.test": {"A": ["127.0.0.1"]}})

        # Provide a tiny custom wordlist containing 'wwwfoo' and 'admin' so that:
        # - 'wwwfoo' would be a false positive without the keyword-based wildcard detection
        # - 'admin' will be an exact match we deliberately allow via the response handler
        from .base import tempwordlist

        words = ["wwwfoo", "admin"]
        wl = tempwordlist(words)

        # Patch virtualhost to use our custom wordlist and inject resolved hosts
        vh_module = module_test.scan.modules["virtualhost"]
        original_setup = vh_module.setup

        async def patched_setup():
            await original_setup()
            vh_module.brute_wordlist = wl
            return True

        module_test.monkeypatch.setattr(vh_module, "setup", patched_setup)

        # Emit URL event manually and ensure resolved_hosts
        from bbot.modules.base import BaseModule

        class DummyModule(BaseModule):
            _name = "dummy_module_keyword"
            watched_events = ["SCAN"]

            async def handle_event(self, event):
                if event.type == "SCAN":
                    url_event = self.scan.make_event(
                        "http://acme.test:8888/",
                        "URL",
                        parent=event,
                        tags=["status-404", "ip-127.0.0.1"],
                    )
                    await self.emit_event(url_event)

        module_test.scan.modules["dummy_module_keyword"] = DummyModule(module_test.scan)

        # Inject resolved hosts for the URL
        orig_handle_event = vh_module.handle_event

        async def patched_handle_event(ev):
            ev._resolved_hosts = {"127.0.0.1"}
            return await orig_handle_event(ev)

        module_test.monkeypatch.setattr(vh_module, "handle_event", patched_handle_event)

    def request_handler(self, request):
        host_header = request.headers.get("Host", "").lower()

        # Baseline response for original host
        if not host_header or host_header in ["acme.test", "acme.test:8888"]:
            return Response("baseline not found", status=404)

        # If hostname contains 'www' anywhere, return the same body as baseline (simulating keyword wildcard)
        if "www" in host_header:
            return Response("baseline not found", status=404)

        # Exact-match virtual host that should still be detected
        if host_header in ["admin.acme.test", "admin.acme.test:8888"]:
            return Response("Admin portal", status=200)

        # Default
        return Response("default response", status=404)

    def check(self, module_test, events):
        found_admin = False
        found_www = False
        for e in events:
            if e.type == "VIRTUAL_HOST":
                vhost = e.data.get("virtual_host")
                if vhost == "admin.acme.test":
                    found_admin = True
                if vhost and "www" in vhost:
                    found_www = True

        assert found_admin, "Expected VIRTUAL_HOST for admin.acme.test was not emitted"
        assert not found_www, "No VIRTUAL_HOST should be emitted for 'www' keyword wildcard entries"


class TestVirtualhostHTTPResponse(VirtualhostTestBase):
    """Test virtual host discovery with badsecrets analysis of HTTP_RESPONSE events"""

    targets = ["http://secrets.test:8888"]
    modules_overrides = ["virtualhost", "badsecrets"]
    test_wordlist = ["admin"]
    config_overrides = {
        "modules": {
            "virtualhost": {
                "brute_wordlist": tempwordlist(test_wordlist),
                "subdomain_brute": True,
                "mutation_check": False,
                "special_hosts": False,
                "certificate_sans": False,
                "wordcloud_check": False,
                "require_inaccessible": False,
            }
        }
    }

    async def setup_after_prep(self, module_test):
        # Call parent setup_after_prep to set up the HTTP server with request_handler
        await super().setup_after_prep(module_test)

        # Set up DNS mocking for secrets.test to resolve to 127.0.0.1
        await module_test.mock_dns({"secrets.test": {"A": ["127.0.0.1"]}})

        # Create a dummy module that will emit the URL event during the scan
        from bbot.modules.base import BaseModule

        class DummyModule(BaseModule):
            _name = "dummy_module_secrets"
            watched_events = ["SCAN"]

            async def handle_event(self, event):
                if event.type == "SCAN":
                    # Create and emit URL event for virtualhost module to process
                    url_event = self.scan.make_event(
                        "http://secrets.test:8888/", "URL", parent=event, tags=["status-200", "ip-127.0.0.1"]
                    )
                    await self.emit_event(url_event)

        # Add the dummy module to the scan
        dummy_module = DummyModule(module_test.scan)
        module_test.scan.modules["dummy_module_secrets"] = dummy_module

        # Patch virtualhost to inject resolved_hosts for URL events during the test
        vh_module = module_test.scan.modules["virtualhost"]
        orig_handle_event = vh_module.handle_event

        async def patched_handle_event(ev):
            ev._resolved_hosts = {"127.0.0.1"}
            return await orig_handle_event(ev)

        module_test.monkeypatch.setattr(vh_module, "handle_event", patched_handle_event)

    def request_handler(self, request):
        from werkzeug.wrappers import Response

        host_header = request.headers.get("Host", "").lower()

        # Baseline request to secrets.test (with or without port)
        if not host_header or host_header in ["secrets.test", "secrets.test:8888"]:
            return Response("baseline response from secrets.test", status=200)

        # Wildcard canary check - change one character in secrets.test
        if re.match(r"[a-z]ecrets\.test", host_header):
            return Response("wildcard canary different response", status=404)

        # Brute-force canary requests - random string + .secrets.test (with optional port)
        if re.match(r"^[a-z]{12}\.secrets\.test(?::8888)?$", host_header):
            return Response("subdomain canary response", status=404)

        # Virtual host with vulnerable JWT cookie and JWT in body - both using weak secret '1234' - this should trigger badsecrets twice
        if host_header in ["admin.secrets.test", "admin.secrets.test:8888"]:
            return Response(
                "<html><body><p>Admin Panel</p><script>const session = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjMsInVzZXJuYW1lIjoiYWRtaW4iLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.03xPSXavrMk0HK4BD3_hPKgu3RLu6CmTSPGfrDx2qpg';</script></body></html>",
                status=200,
                headers={
                    "set-cookie": "vulnjwt=eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo; secure"
                },
            )

        # Default response
        return Response("default response", status=404)

    def check(self, module_test, events):
        virtual_host_found = False
        http_response_found = False
        jwt_cookie_vuln_found = False
        jwt_body_vuln_found = False

        # Debug: print all events to see what we're getting
        print(f"\n=== DEBUG: Found {len(events)} events ===")
        for e in events:
            print(f"Event: {e.type} - {e.data}")
            if hasattr(e, "tags"):
                print(f"  Tags: {e.tags}")

        for e in events:
            # Check for virtual host discovery
            if e.type == "VIRTUAL_HOST":
                vhost = e.data["virtual_host"]
                if vhost in ["admin.secrets.test"]:
                    virtual_host_found = True
                    # Verify it has the virtual-host tag
                    assert "virtual-host" in e.tags, f"VIRTUAL_HOST event missing virtual-host tag: {e.tags}"

            # Check for HTTP_RESPONSE with virtual-host tag
            elif e.type == "HTTP_RESPONSE":
                if "virtual-host" in e.tags:
                    http_response_found = True
                    # Verify the HTTP_RESPONSE has the expected format
                    assert "input" in e.data, f"HTTP_RESPONSE missing input field: {e.data}"
                    assert e.data["input"] == "admin.secrets.test", f"HTTP_RESPONSE input mismatch: {e.data['input']}"
                    assert "status_code" in e.data, f"HTTP_RESPONSE missing status_code: {e.data}"
                    assert e.data["status_code"] == 200, f"HTTP_RESPONSE status_code mismatch: {e.data['status_code']}"
                    # Debug: print the response data to see what badsecrets is analyzing
                    print(f"HTTP_RESPONSE data: {e.data}")

            # Check for badsecrets findings
            elif e.type == "FINDING":
                print(f"Found FINDING event: {e.data}")
                description = e.data["description"]

                # Check for JWT vulnerability (from cookie)
                if (
                    "1234" in description
                    and "eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo"
                    in description
                    and "JWT" in description
                ):
                    jwt_cookie_vuln_found = True

                # Check for JWT vulnerability (from body)
                if (
                    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjMsInVzZXJuYW1lIjoiYWRtaW4iLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.03xPSXavrMk0HK4BD3_hPKgu3RLu6CmTSPGfrDx2qpg"
                    in description
                    and "JWT" in description
                ):
                    jwt_body_vuln_found = True

        assert virtual_host_found, "Failed to detect virtual host admin.secrets.test"
        assert http_response_found, "Failed to detect HTTP_RESPONSE event with virtual-host tag"
        assert jwt_cookie_vuln_found, (
            "Failed to detect JWT vulnerability - JWT with weak secret '1234' should have been found"
        )
        assert jwt_body_vuln_found, (
            "Failed to detect JWT vulnerability in body - JWT 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjMsInVzZXJuYW1lIjoiYWRtaW4iLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.03xPSXavrMk0HK4BD3_hPKgu3RLu6CmTSPGfrDx2qpg' should have been found"
        )
        print(
            f"Test results: virtual_host_found={virtual_host_found}, http_response_found={http_response_found}, jwt_cookie_vuln_found={jwt_cookie_vuln_found}, jwt_body_vuln_found={jwt_body_vuln_found}"
        )


class TestVirtualhostFinishNoneBaseline(VirtualhostTestBase):
    """Regression: finish() must not crash when _get_baseline_response returns None.

    Previously, finish() passed the baseline response straight into
    _wildcard_canary_check without a null check. A failed baseline request
    surfaced as: `'NoneType' object has no attribute 'status_code'`.
    """

    targets = ["http://finishnone.test:8888"]
    modules_overrides = ["http", "virtualhost"]
    config_overrides = {
        "modules": {
            "virtualhost": {
                "subdomain_brute": False,
                "mutation_check": False,
                "special_hosts": False,
                "certificate_sans": False,
                "wordcloud_check": True,
                "require_inaccessible": False,
            }
        }
    }

    async def setup_after_prep(self, module_test):
        await super().setup_after_prep(module_test)

        await module_test.mock_dns({"finishnone.test": {"A": ["127.0.0.1"]}})

        def mock_wordcloud_keys(self):
            return ["staging", "prod", "dev"]

        module_test.monkeypatch.setattr("bbot.core.helpers.wordcloud.WordCloud.keys", mock_wordcloud_keys)

        vh_module = module_test.scan.modules["virtualhost"]
        original_get_baseline = vh_module._get_baseline_response
        original_wildcard_check = vh_module._wildcard_canary_check
        self.baseline_calls = 0
        self.wildcard_check_probes = []

        async def flaky_baseline(event, normalized_url, host_ip):
            self.baseline_calls += 1
            # First call (from handle_event) returns a real response so the
            # host gets recorded in scanned_hosts. Subsequent calls (from
            # finish()) return None to reproduce the crash.
            if self.baseline_calls == 1:
                return await original_get_baseline(event, normalized_url, host_ip)
            return None

        async def spying_wildcard_check(probe_scheme, probe_host, event, host_ip, probe_response):
            self.wildcard_check_probes.append(probe_response)
            return await original_wildcard_check(probe_scheme, probe_host, event, host_ip, probe_response)

        module_test.monkeypatch.setattr(vh_module, "_get_baseline_response", flaky_baseline)
        module_test.monkeypatch.setattr(vh_module, "_wildcard_canary_check", spying_wildcard_check)

        from bbot.modules.base import BaseModule

        class DummyModule(BaseModule):
            _name = "dummy_module_finish_none"
            watched_events = ["SCAN"]

            async def handle_event(self, event):
                if event.type == "SCAN":
                    url_event = self.scan.make_event(
                        "http://finishnone.test:8888/",
                        "URL",
                        parent=event,
                        tags=["status-200", "ip-127.0.0.1"],
                    )
                    await self.emit_event(url_event)

        module_test.scan.modules["dummy_module_finish_none"] = DummyModule(module_test.scan)

        orig_handle_event = vh_module.handle_event

        async def patched_handle_event(ev):
            ev._resolved_hosts = {"127.0.0.1"}
            return await orig_handle_event(ev)

        module_test.monkeypatch.setattr(vh_module, "handle_event", patched_handle_event)

    def request_handler(self, request):
        host_header = request.headers.get("Host", "").lower()

        if not host_header or host_header in ["finishnone.test", "finishnone.test:8888"]:
            return Response("baseline response from finishnone.test", status=200)

        if re.match(r"[a-z]inishnone\.test(?::8888)?$", host_header):
            return Response("wildcard canary response", status=404)

        if re.match(r"^[a-z]{12}\.com(?::8888)?$", host_header):
            return Response("random canary response", status=404)

        return Response("default response", status=404)

    def check(self, module_test, events):
        assert self.baseline_calls >= 2, (
            f"finish() wordcloud path did not run; only {self.baseline_calls} baseline call(s)"
        )
        # finish() must guard against None baseline_response before calling
        # _wildcard_canary_check. Passing None causes the crash.
        assert None not in self.wildcard_check_probes, (
            "finish() invoked _wildcard_canary_check with probe_response=None; "
            "expected the None baseline to be skipped instead"
        )


class TestVirtualhostCertificateSANs(VirtualhostTestBase):
    """Exercise the certificate-SAN code path on HTTPS URL events."""

    targets = ["https://localhost:9999"]
    modules_overrides = ["virtualhost"]
    config_overrides = {
        "modules": {
            "virtualhost": {
                "subdomain_brute": False,
                "mutation_check": False,
                "special_hosts": False,
                "certificate_sans": True,
                "wordcloud_check": False,
                "require_inaccessible": False,
            }
        }
    }

    async def setup_after_prep(self, module_test):
        self.captured_san_arg = []

        vh_module = module_test.scan.modules["virtualhost"]
        captured = self.captured_san_arg

        async def fake_analyze(arg):
            captured.append(arg)
            return []

        async def fake_baseline(event, normalized_url, host_ip):
            return {"http_code": 200, "response_data": "baseline", "url": normalized_url}

        async def fake_wildcard_check(scheme, host, event, host_ip, baseline):
            return True

        module_test.monkeypatch.setattr(vh_module, "_analyze_subject_alternate_names", fake_analyze)
        module_test.monkeypatch.setattr(vh_module, "_get_baseline_response", fake_baseline)
        module_test.monkeypatch.setattr(vh_module, "_wildcard_canary_check", fake_wildcard_check)

        from bbot.modules.base import BaseModule

        class DummyModule(BaseModule):
            _name = "dummy_module_sans"
            watched_events = ["SCAN"]

            async def handle_event(self, event):
                if event.type == "SCAN":
                    url_event = self.scan.make_event(
                        "https://localhost:9999/",
                        "URL",
                        parent=event,
                        tags=["status-200", "ip-127.0.0.1"],
                    )
                    await self.emit_event(url_event)

        module_test.scan.modules["dummy_module_sans"] = DummyModule(module_test.scan)

        orig_handle_event = vh_module.handle_event

        async def patched_handle_event(ev):
            ev._resolved_hosts = {"127.0.0.1"}
            return await orig_handle_event(ev)

        module_test.monkeypatch.setattr(vh_module, "handle_event", patched_handle_event)

    def check(self, module_test, events):
        assert self.captured_san_arg, "SAN analyzer was never invoked on the HTTPS URL event"
        san_arg = self.captured_san_arg[0]
        assert isinstance(san_arg, str), (
            f"SAN analyzer received {type(san_arg).__name__}, expected str. Value: {san_arg!r}"
        )
        assert san_arg.startswith("https://"), f"Expected HTTPS URL, got {san_arg!r}"


class TestVirtualhostSkipsCdnWaf(VirtualhostTestBase):
    """filter_event must reject URLs tagged with any of the flat cloud-provider tags
    that cloudcheck emits (post-`Migrate cloudcheck to host_metadata` refactor)."""

    targets = ["http://localhost:8888"]
    modules_overrides = ["virtualhost"]

    async def setup_after_prep(self, module_test):
        pass

    async def check(self, module_test, events):
        vh_module = module_test.scan.modules["virtualhost"]

        for tag in ("cloudflare", "imperva", "akamai", "cloudfront"):
            url_event = module_test.scan.make_event(
                "http://cdn-test.local:8888/",
                "URL",
                parent=module_test.scan.root_event,
                tags=[tag, "in-scope", "status-200"],
            )
            result = await vh_module.filter_event(url_event)
            assert result is False, f"virtualhost must skip URL tagged {tag!r} (got {result!r})"

        untagged_event = module_test.scan.make_event(
            "http://plain.local:8888/",
            "URL",
            parent=module_test.scan.root_event,
            tags=["in-scope", "status-200"],
        )
        result = await vh_module.filter_event(untagged_event)
        assert result is True, f"virtualhost must not skip an untagged URL (got {result!r})"
