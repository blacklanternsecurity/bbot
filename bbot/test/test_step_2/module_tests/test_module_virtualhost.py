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
    modules_overrides = ["httpx", "virtualhost"]
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

    def request_handler(self, request):
        host_header = request.headers.get("Host", "").lower()

        # Baseline request to localhost
        if not host_header or host_header == "localhost:8888":
            return Response("baseline response from localhost", status=200)

        # Wildcard canary check
        if re.match(r"[a-z]ocalhost:8888", host_header):
            return Response("different wildcard response", status=404)

        # Random canary requests (12 lowercase letters .com)
        if re.match(r"[a-z]{12}\.com", host_header):
            return Response("canary response for random", status=404)

        # Special hosts responses - return different content than canary
        if host_header == "host.docker.internal":
            return Response("Docker internal host active", status=200)
        if host_header == "127.0.0.1":
            return Response("Loopback host active", status=200)
        if host_header == "localhost":
            return Response("Localhost virtual host active", status=200)

        # Default for any other requests
        return Response("default response", status=404)

    def check(self, module_test, events):
        special_hosts_found = set()
        for e in events:
            if e.type == "VIRTUAL_HOST":
                vhost = e.data["virtual_host"]
                if vhost in ["host.docker.internal", "127.0.0.1", "localhost"]:
                    special_hosts_found.add(vhost)

                    # Test description elements to ensure they are as expected
                    description = e.data["description"]
                    assert "Discovery Technique: [Special virtual host list" in description, (
                        f"Description missing discovery technique: {description}"
                    )
                    assert "Status Code:" in description, f"Description missing status code: {description}"
                    assert "Size:" in description and "bytes" in description, (
                        f"Description missing size: {description}"
                    )
                    assert "IP: 127.0.0.1" in description, f"Description missing IP: {description}"
                    assert "Access:" in description, f"Description missing access status: {description}"

        assert len(special_hosts_found) >= 1, f"Failed to detect special virtual hosts. Found: {special_hosts_found}"


class TestVirtualhostBruteForce(VirtualhostTestBase):
    """Test subdomain brute-force detection using HTTP Host headers without DNS resolution"""

    targets = ["http://127.0.0.1:8888"]  # Use IP to avoid DNS resolution
    modules_overrides = ["httpx", "virtualhost"]
    test_wordlist = ["admin", "api", "test"]
    config_overrides = {
        "modules": {
            "virtualhost": {
                "brute_wordlist": tempwordlist(test_wordlist),
                "force_basehost": "localhost",  # Force basehost to avoid DNS issues
                "subdomain_brute": True,  # Enable brute force
                "mutation_check": False,  # Focus on brute force only
                "special_hosts": False,  # Focus on brute force only
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
            return Response("baseline response from 127.0.0.1", status=200)

        # Wildcard canary check - using forced basehost "localhost"
        if re.match(r"[0-9]27\.0\.0\.1:8888", host_header):  # Modified basehost
            return Response("wildcard canary different response", status=404)

        # Brute-force canary requests - random string + .localhost
        if re.match(r"[a-z]{12}\.localhost:8888", host_header):
            return Response("subdomain canary response", status=404)

        # Brute-force matches - return different content than canary
        if host_header in ["admin.localhost", "admin.localhost:8888"]:
            return Response("Admin panel found here!", status=200)
        if host_header in ["api.localhost", "api.localhost:8888"]:
            return Response("API endpoint found here!", status=200)
        if host_header in ["test.localhost", "test.localhost:8888"]:
            return Response("Test environment found here!", status=200)

        # Default response
        return Response("default response", status=404)

    def check(self, module_test, events):
        brute_hosts_found = set()
        for e in events:
            if e.type == "VIRTUAL_HOST":
                vhost = e.data["virtual_host"]
                if vhost in ["admin.localhost", "api.localhost", "test.localhost"]:
                    brute_hosts_found.add(vhost)

        assert len(brute_hosts_found) >= 1, f"Failed to detect brute-force virtual hosts. Found: {brute_hosts_found}"


class TestVirtualhostMutations(VirtualhostTestBase):
    """Test host mutation detection using HTTP Host headers without DNS resolution"""

    targets = ["http://127.0.0.1:8888"]  # Use IP to avoid DNS resolution
    modules_overrides = ["httpx", "virtualhost"]
    config_overrides = {
        "modules": {
            "virtualhost": {
                "force_basehost": "localhost",  # Force basehost to avoid DNS issues
                "subdomain_brute": False,  # Focus on mutations only
                "mutation_check": True,  # Enable mutations
                "special_hosts": False,  # Focus on mutations only
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
            return Response("baseline response from 127.0.0.1", status=200)

        # Wildcard canary check
        if re.match(r"[0-9]27\.0\.0\.1:8888", host_header):  # Modified IP
            return Response("wildcard canary response", status=404)

        # Mutation canary requests (4 chars + dash + original host)
        if re.match(r"[a-z]{4}-127\.0\.0\.1:8888", host_header):
            return Response("mutation canary response", status=404)

        # Word cloud mutation matches - return different content than canary
        if host_header in ["127dev.localhost:8888", "127-dev.localhost:8888"]:
            return Response("Development 127 found!", status=200)
        if host_header in ["dev127.localhost:8888", "dev-127.localhost:8888"]:
            return Response("Dev 127 found!", status=200)
        if host_header in ["127test.localhost:8888", "127-test.localhost:8888"]:
            return Response("Test 127 found!", status=200)

        # Default response
        return Response("default response", status=404)

    async def setup_before_prep(self, module_test):
        # Call parent setup first
        await super().setup_before_prep(module_test)

        # Mock wordcloud.mutations to return predictable results for IP-based target
        def mock_mutations(self, word, **kwargs):
            # Return realistic mutations that would be found for "127"
            return [
                [word, "dev"],  # 127dev, 127-dev
                ["dev", word],  # dev127, dev-127
                [word, "test"],  # 127test, 127-test
            ]

        module_test.monkeypatch.setattr("bbot.core.helpers.wordcloud.WordCloud.mutations", mock_mutations)

    def check(self, module_test, events):
        mutation_hosts_found = set()
        for e in events:
            if e.type == "VIRTUAL_HOST":
                vhost = e.data["virtual_host"]
                # Look for mutation patterns with dev/test
                if any(word in vhost for word in ["dev", "test"]) and "127" in vhost:
                    mutation_hosts_found.add(vhost)

        assert len(mutation_hosts_found) >= 1, (
            f"Failed to detect mutation virtual hosts. Found: {mutation_hosts_found}"
        )


class TestVirtualhostWordcloud(VirtualhostTestBase):
    """Test finish() wordcloud-based detection using HTTP Host headers without DNS resolution"""

    targets = ["http://127.0.0.1:8888"]  # Use IP to avoid DNS resolution
    modules_overrides = ["httpx", "virtualhost"]
    config_overrides = {
        "modules": {
            "virtualhost": {
                "force_basehost": "localhost",  # Force basehost to avoid DNS issues
                "subdomain_brute": False,  # Focus on wordcloud only
                "mutation_check": False,  # Focus on wordcloud only
                "special_hosts": False,  # Focus on wordcloud only
                "certificate_sans": False,
                "wordcloud_check": True,  # Enable wordcloud
                "require_inaccessible": False,
            }
        }
    }

    def request_handler(self, request):
        host_header = request.headers.get("Host", "").lower()

        # Baseline request to the IP
        if not host_header or host_header == "127.0.0.1:8888":
            return Response("baseline response from 127.0.0.1", status=200)

        # Wildcard canary check
        if re.match(r"[0-9]27\.0\.0\.1:8888", host_header):  # Modified IP
            return Response("wildcard canary response", status=404)

        # Random canary requests (12 chars + .com)
        if re.match(r"[a-z]{12}\.com", host_header):
            return Response("random canary response", status=404)

        # Wordcloud-based matches - these are checked in finish()
        if host_header == "staging.localhost:8888":
            return Response("Staging environment found!", status=200)
        if host_header == "prod.localhost:8888":
            return Response("Production environment found!", status=200)
        if host_header == "dev.localhost:8888":
            return Response("Development environment found!", status=200)

        # Default response
        return Response("default response", status=404)

    async def setup_before_prep(self, module_test):
        # Call parent setup first
        await super().setup_before_prep(module_test)

        # Mock wordcloud to have some common words
        def mock_wordcloud_keys(self):
            return ["staging", "prod", "dev", "admin", "api"]

        module_test.monkeypatch.setattr("bbot.core.helpers.wordcloud.WordCloud.keys", mock_wordcloud_keys)

    def check(self, module_test, events):
        wordcloud_hosts_found = set()
        for e in events:
            if e.type == "VIRTUAL_HOST":
                vhost = e.data["virtual_host"]
                if vhost in ["staging.localhost", "prod.localhost", "dev.localhost"]:
                    wordcloud_hosts_found.add(vhost)

        assert len(wordcloud_hosts_found) >= 1, (
            f"Failed to detect wordcloud virtual hosts. Found: {wordcloud_hosts_found}"
        )


class TestVirtualhostHTTPSLogic(ModuleTestBase):
    """Unit tests for HTTPS/SNI-specific functions"""

    targets = ["http://localhost:8888"]  # Minimal target for unit testing
    modules_overrides = ["httpx", "virtualhost"]

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
