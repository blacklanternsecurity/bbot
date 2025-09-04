from rapidfuzz import fuzz
from urllib.parse import urlparse
import random
import string
import xxhash

from bbot.modules.base import BaseModule
from bbot.errors import CurlError


class virtualhost(BaseModule):
    watched_events = ["URL"]
    produced_events = ["VIRTUAL_HOST", "DNS_NAME"]
    flags = ["active", "aggressive", "slow", "deadly"]
    meta = {"description": "Fuzz for virtual hosts", "created_date": "2022-05-02", "author": "@liquidsec"}

    deps_pip = ["rapidfuzz", "xxhash"]
    deps_common = ["curl"]

    SIMILARITY_THRESHOLD = 0.6
    CANARY_LENGTH = 12

    special_virtualhost_list = ["127.0.0.1", "localhost", "host.docker.internal"]
    options = {
        "brute_wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
        "force_basehost": "",
        "brute_lines": 2000,
        "subdomain_brute": False,
        "mutation_check": True,
        "special_hosts": True,
        "certificate_sans": True,
        "max_concurrent_requests": 80,
        "require_inaccessible": True,
        "wordcloud_check": True,
    }
    options_desc = {
        "brute_wordlist": "Wordlist containing subdomains",
        "force_basehost": "Use a custom base host (e.g. evilcorp.com) instead of the default behavior of using the current URL",
        "brute_lines": "take only the first N lines from the wordlist when finding directories",
        "subdomain_brute": "Enable subdomain brute-force on target host",
        "mutation_check": "Enable mutations check on target host",
        "special_hosts": "Enable testing of special virtual host list (localhost, etc.)",
        "certificate_sans": "Enable extraction and testing of Subject Alternative Names from certificates",
        "wordcloud_check": "Enable check using scan-wide wordcloud data on target host",
        "max_concurrent_requests": "Maximum number of concurrent virtual host requests",
        "require_inaccessible": "Only test virtual hosts that are not directly accessible (for discovering hidden content)",
    }

    in_scope_only = True

    virtualhost_ignore_strings = [
        "We weren't able to find your Azure Front Door Service",
        "The http request header is incorrect.",
    ]

    async def setup(self):
        self.max_concurrent = self.config.get("max_concurrent_requests", 80)
        self.scanned_hosts = {}
        self.wordcloud_tried_hosts = set()
        self.brute_wordlist = await self.helpers.wordlist(
            self.config.get("brute_wordlist"), lines=self.config.get("brute_lines", 2000)
        )
        self.similarity_cache = {}  # Cache for similarity results

        self.waf_strings = self.helpers.get_waf_strings() + self.virtualhost_ignore_strings

        return True

    async def handle_event(self, event):
        if not self.helpers.is_ip(event.host) or self.config.get("force_basehost"):
            scheme = event.parsed_url.scheme
            host = event.parsed_url.netloc
            normalized_url = f"{scheme}://{host}"

            # since we normalize the URL to the host level,
            if normalized_url in self.scanned_hosts:
                return

            self.scanned_hosts[normalized_url] = event

            if self.config.get("force_basehost"):
                basehost = self.config.get("force_basehost")
            else:
                basehost = self.helpers.parent_domain(event.parsed_url.netloc)
            is_https = event.parsed_url.scheme == "https"

            host_ip = next(iter(event.resolved_hosts))
            baseline_response = await self.helpers.web.curl(url=f"{event.parsed_url.scheme}://{basehost}")

            if not await self._wildcard_canary_check(scheme, host, event, host_ip, baseline_response):
                self.verbose(f"Skipping {normalized_url} - failed virtual host wildcard check")
                return None

            # Phase 1: Main virtual host bruteforce
            if self.config.get("subdomain_brute", True):
                self.verbose(f"=== Starting subdomain brute-force on {normalized_url} ===")
                await self._run_virtualhost_phase(
                    "Target host Subdomain Brute-force",
                    normalized_url,
                    f".{basehost}",
                    host_ip,
                    is_https,
                    event,
                    "subdomain",
                    with_mutations=True,
                )

            # Phase 2: Check existing host for mutations
            if self.config.get("mutation_check", True):
                self.verbose(f"=== Starting mutations check on {normalized_url} ===")
                await self._run_virtualhost_phase(
                    "Mutations on target host",
                    normalized_url,
                    f".{basehost}",
                    host_ip,
                    is_https,
                    event,
                    "mutation",
                    wordlist=self.mutations_check(event.parsed_url.netloc.split(".")[0]),
                )

            # Phase 3: Special virtual host list
            if self.config.get("special_hosts", True):
                self.verbose(f"=== Starting special virtual hosts check on {normalized_url} ===")
                await self._run_virtualhost_phase(
                    "Special virtual host list",
                    normalized_url,
                    "",
                    host_ip,
                    is_https,
                    event,
                    "random",
                    wordlist=self.helpers.tempfile(self.special_virtualhost_list, pipe=False),
                    skip_dns_host=True,
                )

            # Phase 4: Obtain subject alternate names from certicate and analyze them
            if self.config.get("certificate_sans", True):
                self.verbose(f"=== Starting certificate SAN analysis on {normalized_url} ===")
                if is_https:
                    subject_alternate_names = await self._analyze_subject_alternate_names(event.data)
                    if subject_alternate_names:
                        self.debug(
                            f"Found {len(subject_alternate_names)} Subject Alternative Names from certificate: {subject_alternate_names}"
                        )

                        # Use SANs as potential virtual hosts for testing
                        san_wordlist = self.helpers.tempfile(subject_alternate_names, pipe=False)
                        await self._run_virtualhost_phase(
                            "Certificate Subject Alternate Name",
                            normalized_url,
                            "",
                            host_ip,
                            is_https,
                            event,
                            "random",
                            wordlist=san_wordlist,
                            skip_dns_host=True,
                        )

    async def _analyze_subject_alternate_names(self, url):
        """Analyze subject alternate names from certificate"""
        from OpenSSL import crypto
        from bbot.modules.sslcert import sslcert

        parsed = urlparse(url)
        host = parsed.netloc

        response = await self.helpers.web.curl(url=url)
        if not response or not response.get("certs"):
            self.debug(f"No certificate data available for {url}")
            return []

        cert_output = response["certs"]
        subject_alt_names = []

        try:
            cert_lines = cert_output.split("\n")
            pem_lines = []
            in_cert = False

            for line in cert_lines:
                if "-----BEGIN CERTIFICATE-----" in line:
                    in_cert = True
                    pem_lines.append(line)
                elif "-----END CERTIFICATE-----" in line:
                    pem_lines.append(line)
                    break
                elif in_cert:
                    pem_lines.append(line)

            if pem_lines:
                cert_pem = "\n".join(pem_lines)
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

                # Use the existing SAN extraction method from sslcert module
                sans = sslcert.get_cert_sans(cert)

                for san in sans:
                    self.debug(f"Found SAN: {san}")
                    if san != host and san not in subject_alt_names:
                        subject_alt_names.append(san)
            else:
                self.debug("No valid PEM certificate found in response")

        except Exception as e:
            self.warning(f"Error parsing certificate for {url}: {e}")

        self.debug(
            f"Found {len(subject_alt_names)} Subject Alternative Names: {subject_alt_names} (besides original target host {host})"
        )
        return subject_alt_names

    def _get_canary_random_host(self, host, basehost, mode="subdomain"):
        """Generate a random host for the canary"""
        # Seed RNG with domain to get consistent canary hosts for same domain
        random.seed(host)

        # Generate canary hostname based on mode
        if mode == "mutation":
            # Prepend random 4-character string with dash to existing hostname
            random_prefix = "".join(random.choice(string.ascii_lowercase) for i in range(4))
            canary_host = f"{random_prefix}-{host}"
        elif mode == "subdomain":
            # Default subdomain mode - add random subdomain
            canary_host = (
                "".join(random.choice(string.ascii_lowercase) for i in range(self.CANARY_LENGTH)) + f".{basehost}"
            )
        elif mode == "random":
            # Fully random hostname with .com TLD
            random_host = "".join(random.choice(string.ascii_lowercase) for i in range(self.CANARY_LENGTH))
            canary_host = f"{random_host}.com"
        else:
            raise ValueError(f"Invalid canary mode: {mode}")

        return canary_host

    async def _get_canary_response(self, normalized_url, basehost, host_ip, is_https, mode="subdomain"):
        """Setup canary response for comparison using the appropriate technique. Returns canary response or None on failure."""

        parsed = urlparse(normalized_url)
        host = parsed.netloc

        # Seed RNG with domain to get consistent canary hosts for same domain
        canary_host = self._get_canary_random_host(host, basehost, mode)

        # Get canary response
        if is_https:
            port = parsed.port or 443
            canary_response = await self.helpers.web.curl(
                url=f"https://{canary_host}:{port}/",
                resolve={"host": canary_host, "port": port, "ip": host_ip},
            )
        else:
            canary_response = await self.helpers.web.curl(url=normalized_url, headers={"Host": canary_host})

        return canary_response

    async def _is_host_accessible(self, url):
        """
        Check if a URL is already accessible via direct HTTP request.
        Returns True if the host is accessible (and should be skipped), False otherwise.
        """
        try:
            response = await self.helpers.web.curl(url=url)
            if response and int(response.get("http_code", 0)) > 0:
                return True
            else:
                return False
        except CurlError as e:
            self.debug(f"Error checking accessibility of {url}: {e}")
            return False

    async def _wildcard_canary_check(self, probe_scheme, probe_host, event, host_ip, probe_response):
        """Change one char in probe_host and test - if responses are similar, it's probably a wildcard"""

        # Find first alphabetic character and change it, fallback to first character
        modified_host = None
        for i, char in enumerate(probe_host):
            if char.isalpha():
                new_char = "z" if char != "z" else "a"
                modified_host = probe_host[:i] + new_char + probe_host[i + 1 :]
                break

        if modified_host is None:
            # Fallback: generate random hostname of similar length
            modified_host = "".join(random.choice(string.ascii_lowercase) for _ in range(len(probe_host)))

        # Test modified host
        if probe_scheme == "https":
            port = event.parsed_url.port or 443
            final_canary_response = await self.helpers.web.curl(
                url=f"https://{modified_host}:{port}/", resolve={"host": modified_host, "port": port, "ip": host_ip}
            )
        else:
            final_canary_response = await self.helpers.web.curl(
                url=f"{probe_scheme}://{probe_host}", headers={"Host": modified_host}
            )

        if not final_canary_response or final_canary_response["http_code"] == 0:
            self.debug(f"Wildcard check: {modified_host} failed to respond, assuming {probe_host} is valid")
            return True  # Modified failed, original probably valid

        # Compare original probe response with modified response
        similarity = self.get_content_similarity(probe_response, final_canary_response)
        result = similarity <= self.SIMILARITY_THRESHOLD

        # Only log when wildcard is detected (failure case)
        if not result:
            self.verbose(
                f"Wildcard check: {probe_host} vs {modified_host} similarity: {similarity:.3f} (threshold: {self.SIMILARITY_THRESHOLD}) -> FAIL (wildcard detected)"
            )
        return result  # True if they're different (good), False if similar (wildcard)

    async def _run_virtualhost_phase(
        self,
        discovery_method,
        normalized_url,
        basehost,
        host_ip,
        is_https,
        event,
        canary_mode,
        wordlist=None,
        skip_dns_host=False,
        with_mutations=False,
    ):
        """Helper method to run a virtual host discovery phase and optionally mutations"""

        canary_response = await self._get_canary_response(
            normalized_url, basehost, host_ip, is_https, mode=canary_mode
        )

        if not canary_response:
            self.debug(f"Failed to get canary response for {normalized_url}, skipping virtual host detection")
            return []

        # Main discovery phase
        results = await self.curl_virtualhost(
            discovery_method,
            normalized_url,
            basehost,
            event,
            canary_response,
            canary_mode,
            wordlist,
            skip_dns_host,
        )
        if results:
            if with_mutations:
                for virtual_host_data in results:
                    mutation_wordlist = self.mutations_check(virtual_host_data["probe_host"])
                    if mutation_wordlist:
                        self.verbose(f"=== Starting mutations for {virtual_host_data['probe_host']} ===")
                        mutation_results = await self.curl_virtualhost(
                            f"Mutations on {virtual_host_data['probe_host']}",
                            normalized_url,
                            basehost,
                            event,
                            canary_response,
                            canary_mode,
                            wordlist=mutation_wordlist,
                            skip_dns_host=skip_dns_host,
                        )
                        if mutation_results:
                            results.extend(mutation_results)

        # Final safeguard: check total result count
        max_results = 50  # Configurable threshold
        if len(results) > max_results:
            self.warning(
                f"Found {len(results)} virtual hosts for host {event.host} (limit: {max_results}), likely false positives - rejecting all results"
            )
            return []

        # Emit all valid results
        for virtual_host_data in results:
            # Emit VIRTUAL_HOST event
            await self.emit_event(
                virtual_host_data["virtualhost_dict"],
                "VIRTUAL_HOST",
                parent=event,
                context=f"{{module}} discovered virtual host via {virtual_host_data['discovery_method']} for {event.data} and found {{event.type}}: {virtual_host_data['probe_host']} (similarity: {virtual_host_data['similarity']:.2%})",
            )

            # Emit DNS_NAME_UNVERIFIED event if needed
            if virtual_host_data["skip_dns_host"] is False:
                await self.emit_event(
                    virtual_host_data["virtualhost_dict"]["virtual_host"],
                    "DNS_NAME_UNVERIFIED",
                    parent=event,
                    tags=["virtual-host"],
                    context=f"{{module}} discovered virtual host via {virtual_host_data['discovery_method']} for {event.data} and found {{event.type}}: {{event.data}}",
                )

    def _generate_virtualhost_coroutines(
        self,
        candidates_to_check,
        host_ips,
        normalized_url,
        basehost,
        event,
        canary_response,
        canary_mode,
        skip_dns_host,
        discovery_method,
    ):
        """Generator that yields virtual host test coroutines on-demand"""
        for host_ip in host_ips:
            for probe_host in candidates_to_check:
                yield self._safe_test_virtualhost(
                    normalized_url,
                    probe_host,
                    basehost,
                    event,
                    canary_response,
                    canary_mode,
                    skip_dns_host,
                    host_ip,
                    discovery_method,
                )

    async def curl_virtualhost(
        self,
        discovery_method,
        normalized_url,
        basehost,
        event,
        canary_response,
        canary_mode,
        wordlist=None,
        skip_dns_host=False,
    ):
        if wordlist is None:
            wordlist = self.brute_wordlist

        # Get baseline host for comparison and determine scheme from event
        baseline_host = event.parsed_url.netloc

        # Collect all words for concurrent processing
        candidates_to_check = []
        for word in self.helpers.read_file(wordlist):
            word = word.strip()
            if not word:
                continue
            # Construct virtual host header
            if basehost:
                probe_host = f"{word}{basehost}"
            else:
                probe_host = word

            # Skip if this would be the same as the original host
            if probe_host == baseline_host:
                continue

            candidates_to_check.append(probe_host)

        self.debug(f"Loaded {len(candidates_to_check)} candidates from wordlist for {discovery_method}")

        host_ips = event.resolved_hosts
        total_tests = len(candidates_to_check) * len(host_ips)

        self.debug(
            f"Testing {total_tests} virtual hosts with max {self.max_concurrent} concurrent requests using {discovery_method} against {len(host_ips)} IPs..."
        )

        # Collect all virtual host results before emitting
        virtual_host_results = []

        # Process results as they complete with concurrency control
        try:
            # Use generator to create coroutines on-demand
            coroutine_generator = self._generate_virtualhost_coroutines(
                candidates_to_check,
                host_ips,
                normalized_url,
                basehost,
                event,
                canary_response,
                canary_mode,
                skip_dns_host,
                discovery_method,
            )

            max_results = 50  # Get limit for early exit check

            async for completed in self.helpers.as_completed(coroutine_generator, self.max_concurrent):
                result = await completed
                if result:  # Only append non-None results
                    virtual_host_results.append(result)

                    # Early exit if we're clearly hitting false positives
                    if len(virtual_host_results) >= max_results:
                        self.warning(
                            f"Early exit: found {len(virtual_host_results)} virtual hosts (limit: {max_results}), likely false positives - stopping further tests"
                        )
                        break
        except CurlError as e:
            self.warning(f"CurlError in as_completed, stopping all tests: {e}")
            return []

        # Final safeguard: check result count (now mostly redundant due to early exit)
        max_results = 50  # Configurable threshold
        if len(virtual_host_results) > max_results:
            self.verbose(
                f"Found {len(virtual_host_results)} virtual hosts (limit: {max_results}), likely false positives - rejecting all results"
            )
            return []

        # Return results for emission at _run_virtualhost_phase level
        return virtual_host_results

    async def _safe_test_virtualhost(self, *args, **kwargs):
        """Wrapper that catches CurlError and returns None instead of raising"""
        try:
            return await self._test_virtualhost(*args, **kwargs)
        except CurlError as e:
            self.warning(f"CurlError in virtualhost test (skipping this test): {e}")
            return None

    async def _test_virtualhost(
        self,
        normalized_url,
        probe_host,
        basehost,
        event,
        canary_response,
        canary_mode,
        skip_dns_host,
        host_ip,
        discovery_method,
    ):
        """
        Test a single virtual host candidate using HTTP Host header or HTTPS SNI
        Returns virtual host data if detected, None otherwise
        """
        is_https = event.parsed_url.scheme == "https"

        # Make request - different approach for HTTP vs HTTPS
        if is_https:
            port = event.parsed_url.port or 443
            probe_response = await self.helpers.web.curl(
                url=f"https://{probe_host}:{port}/",
                resolve={"host": probe_host, "port": port, "ip": host_ip},
            )
        else:
            probe_response = await self.helpers.web.curl(
                url=normalized_url,
                headers={"Host": probe_host},
                resolve={"host": probe_host, "port": event.port or 80, "ip": host_ip},
            )

        if not probe_response or probe_response["response_data"] == "":
            protocol = "HTTPS" if is_https else "HTTP"
            self.debug(f"{protocol} probe failed for {probe_host} on ip {host_ip} - no response or empty data")
            return None

        similarity = self.analyze_response(probe_host, probe_response, canary_response, event)
        if similarity is None:
            return None

        # Different from canary = possibly real virtual host, similar to canary = probably junk
        if similarity > self.SIMILARITY_THRESHOLD:
            return None

        # Re-verify canary consistency before emission
        if not await self._verify_canary(
            event, canary_response, canary_mode, normalized_url, probe_host, is_https, basehost, host_ip
        ):
            self.verbose(
                f"Canary changed since initial test, rejecting {probe_host}. Original canary had code {canary_response['http_code']} and response data of length {len(canary_response['response_data'])}"
            )
            raise CurlError(f"Canary changed since initial test, rejecting {probe_host}")

        # Don't emit if this would be the same as the original netloc
        if probe_host != event.parsed_url.netloc:
            # Check if this virtual host is externally accessible
            probe_url = f"{event.parsed_url.scheme}://{probe_host}/"
            is_externally_accessible = await self._is_host_accessible(probe_url)

            virtualhost_dict = {
                "host": str(event.host),
                "url": normalized_url,
                "virtual_host": probe_host,
                "description": self._build_description(
                    discovery_method, probe_response, is_externally_accessible, host_ip
                ),
                "ip": host_ip,
            }

            # Skip if we require inaccessible hosts and this one is accessible
            if self.config.get("require_inaccessible", True) and is_externally_accessible:
                self.verbose(
                    f"Skipping emit for virtual host {probe_host} - is externally accessible and require_inaccessible is True"
                )
                return None

            # Return data for emission at _run_virtualhost_phase level
            technique = "SNI" if is_https else "Host header"
            return {
                "virtualhost_dict": virtualhost_dict,
                "similarity": similarity,
                "probe_host": probe_host,
                "skip_dns_host": skip_dns_host,
                "discovery_method": f"{discovery_method} ({technique})",
            }
        else:
            self.debug(f"SKIPPING {probe_host} - same as original netloc")
            return None

    def analyze_response(self, probe_host, probe_response, canary_response, event):
        probe_status = probe_response["http_code"]
        canary_status = canary_response["http_code"]

        # Check for invalid/no response - skip processing
        if probe_status == 0 or not probe_response.get("response_data"):
            self.debug(f"SKIPPING {probe_host} - no valid HTTP response (status: {probe_status})")
            return None

        # Check for 421 Misdirected Request - clear signal that virtual host doesn't exist
        if probe_status == 421:
            self.debug(f"SKIPPING {probe_host} - got 421 Misdirected Request (SNI not configured)")
            return None

        if probe_status == 502 or probe_status == 503:
            self.debug(f"SKIPPING {probe_host} - got 502 or 503 Bad Gateway")
            return None

        # Check for 403 Forbidden - signal that the virtual host is rejected (unless we started with a 403)
        if probe_status == 403 and canary_status != 403:
            self.debug(f"SKIPPING {probe_host} - got 403 Forbidden when canary status was {canary_status}")
            return None

        if probe_status == 508:
            self.debug(f"SKIPPING {probe_host} - got 508 Loop Detected")
            return None

        # Check for redirects back to original domain - indicates virtual host just redirects to canonical
        if probe_status in [301, 302]:
            redirect_url = probe_response.get("redirect_url", "")
            if str(event.parsed_url.netloc) in redirect_url:
                self.debug(f"SKIPPING {probe_host} - redirects back to original domain {event.parsed_url.netloc}")
                return None

        if any(waf_string in probe_response["response_data"] for waf_string in self.waf_strings):
            self.debug(f"SKIPPING {probe_host} - got WAF response")
            return None

        # Calculate content similarity to canary (junk response)
        similarity = self.get_content_similarity(canary_response, probe_response)

        # Debug logging only when we think we found a match
        if similarity <= self.SIMILARITY_THRESHOLD:
            self.verbose(
                f"POTENTIAL MATCH: {probe_host} vs canary - similarity: {similarity:.3f} (threshold: {self.SIMILARITY_THRESHOLD}), probe status: {probe_status}, canary status: {canary_status}"
            )

        return similarity

    def get_content_similarity(self, canary_response, probe_response):
        # Create fast hashes for cache key using xxHash
        canary_data = canary_response["response_data"]
        probe_data = probe_response["response_data"]

        # Fastest check: exact equality (very common for identical error pages)
        if canary_data == probe_data:
            return 1.0  # Exactly the same

        # Fast pre-filter: if response lengths are drastically different, skip expensive calculation
        canary_len = len(canary_data)
        probe_len = len(probe_data)

        if canary_len > 0 and probe_len > 0:
            length_ratio = min(canary_len, probe_len) / max(canary_len, probe_len)
            if length_ratio < 0.3:  # Very conservative - only skip if >70% length difference
                return 0.0  # Definitely not similar

        canary_hash = xxhash.xxh64(canary_data.encode() if isinstance(canary_data, str) else canary_data).hexdigest()
        probe_hash = xxhash.xxh64(probe_data.encode() if isinstance(probe_data, str) else probe_data).hexdigest()

        # Create cache key (order-independent)
        cache_key = tuple(sorted([canary_hash, probe_hash]))

        # Check cache first
        if cache_key in self.similarity_cache:
            return self.similarity_cache[cache_key]

        # Calculate similarity
        similarity = fuzz.ratio(canary_data, probe_data) / 100.0

        # Cache the result
        self.similarity_cache[cache_key] = similarity

        return similarity

    async def _verify_canary(
        self, event, original_canary_response, canary_mode, normalized_url, probe_host, is_https, basehost, host_ip
    ):
        """Re-test the canary to make sure it's still consistent before emission"""

        # Re-run the same canary test as we did initially
        try:
            current_canary_response = await self._get_canary_response(
                normalized_url, basehost, host_ip, is_https, mode=canary_mode
            )
        except CurlError as e:
            self.warning(f"Canary verification failed due to curl error: {e}")
            return False

        if not current_canary_response:
            return False

        # Check if HTTP codes are different first (hard failure)
        if original_canary_response["http_code"] != current_canary_response["http_code"]:
            self.verbose(
                f"CANARY HTTP CODE CHANGED for {normalized_url} - Original: {original_canary_response.get('http_code', 'N/A')} ({len(original_canary_response.get('response_data', ''))} bytes), Current: {current_canary_response.get('http_code', 'N/A')} ({len(current_canary_response.get('response_data', ''))} bytes)"
            )
            return False

        # if response data is exactly the same, we're good
        if original_canary_response["response_data"] == current_canary_response["response_data"]:
            return True

        # Fallback - use similarity comparison for response data (allows slight differences)
        similarity = self.get_content_similarity(original_canary_response, current_canary_response)
        if similarity < self.SIMILARITY_THRESHOLD:
            self.verbose(
                f"CANARY SIMILARITY CHANGED for {normalized_url} - similarity: {similarity:.3f} below threshold {self.SIMILARITY_THRESHOLD} - Original: {original_canary_response.get('http_code', 'N/A')} ({len(original_canary_response.get('response_data', ''))} bytes), Current: {current_canary_response.get('http_code', 'N/A')} ({len(current_canary_response.get('response_data', ''))} bytes)"
            )
            return False
        return True

    def _extract_title(self, response_data):
        """Extract title from HTML response"""
        soup = self.helpers.beautifulsoup(response_data, "html.parser")
        if soup and soup.title and soup.title.string:
            return soup.title.string.strip()
        return None

    def _build_description(self, discovery_string, probe_response, is_externally_accessible=None, host_ip=None):
        """Build detailed description with discovery technique and content info"""
        http_code = probe_response.get("http_code", "N/A")
        response_size = len(probe_response.get("response_data", ""))

        description = f"Discovery Technique: [{discovery_string}], Discovered Content: [Status Code: {http_code}]"

        # Add title if available
        title = self._extract_title(probe_response.get("response_data", ""))
        if title:
            description += f" [Title: {title}]"
        description += f" [Size: {response_size} bytes]"

        # Add IP address if available
        if host_ip:
            description += f" [IP: {host_ip}]"

        # Add accessibility information if available
        if is_externally_accessible is not None:
            accessibility_status = "externally accessible" if is_externally_accessible else "not externally accessible"
            description += f" [Access: {accessibility_status}]"

        return description

    def mutations_check(self, virtualhost):
        mutations_list = []
        for mutation in self.helpers.word_cloud.mutations(virtualhost, cloud=False):
            mutations_list.extend(["".join(mutation), "-".join(mutation)])
        mutations_list_file = self.helpers.tempfile(mutations_list, pipe=False)
        return mutations_list_file

    async def finish(self):
        # phase 5: check existing hosts with wordcloud
        if not self.config.get("wordcloud_check", True):
            self.debug("Wordcloud check is disabled, skipping finish phase")
            return

        if not self.helpers.word_cloud.keys():
            self.debug("No wordcloud data available for finish phase")
            return

        tempfile = self.helpers.tempfile(list(self.helpers.word_cloud.keys()), pipe=False)
        self.verbose(
            f"Starting wordcloud mutations on {len(self.scanned_hosts)} hosts using {len(list(self.helpers.word_cloud.keys()))} words from wordcloud"
        )

        for host, event in self.scanned_hosts.items():
            if host not in self.wordcloud_tried_hosts:
                event.parsed_url = urlparse(host)

                if self.config.get("force_basehost"):
                    basehost = self.config.get("force_basehost")
                else:
                    basehost = self.helpers.parent_domain(event.parsed_url.netloc)

                # Get fresh canary and original response for this host
                is_https = event.parsed_url.scheme == "https"
                host_ip = next(iter(event.resolved_hosts))

                await self._run_virtualhost_phase(
                    "Target host wordcloud mutations",
                    host,
                    f".{basehost}",
                    host_ip,
                    is_https,
                    event,
                    "random",
                    wordlist=tempfile,
                )
                self.wordcloud_tried_hosts.add(host)

    async def filter_event(self, event):
        if (
            "cdn-cloudflare" in event.tags
            or "cdn-imperva" in event.tags
            or "cdn-akamai" in event.tags
            or "cdn-cloudfront" in event.tags
        ):
            self.debug(f"Not processing URL {event.data} because it's behind a WAF or CDN, and that's pointless")
            return False
        return True
