from urllib.parse import urlparse
import random
import string

from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field
from bbot.core.helpers.simhash import compute_simhash


class virtualhost(BaseModule):
    watched_events = ["URL"]
    produced_events = ["VIRTUAL_HOST", "DNS_NAME_UNVERIFIED", "HTTP_RESPONSE"]
    flags = ["active", "loud", "slow"]
    meta = {"description": "Fuzz for virtual hosts", "created_date": "2022-05-02", "author": "@liquidsec"}

    SIMILARITY_THRESHOLD = 0.8
    CANARY_LENGTH = 12
    MAX_RESULTS_FLOOD_PROTECTION = 50

    special_virtualhost_list = ["127.0.0.1", "localhost", "host.docker.internal"]

    class Config(BaseModuleConfig):
        brute_wordlist: str = Field(
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
            description="Wordlist containing subdomains",
        )
        force_basehost: str = Field(
            "",
            description="Use a custom base host (e.g. evilcorp.com) instead of the default behavior of using the current URL",
        )
        brute_lines: int = Field(
            2000, description="Take only the first N lines from the wordlist when finding directories"
        )
        subdomain_brute: bool = Field(True, description="Enable subdomain brute-force on target host")
        mutation_check: bool = Field(True, description="Enable trying mutations of the target host")
        special_hosts: bool = Field(False, description="Enable testing of special virtual host list (localhost, etc.)")
        certificate_sans: bool = Field(
            False, description="Enable extraction and testing of Subject Alternative Names from certificates"
        )
        max_concurrent_requests: int = Field(80, description="Maximum number of concurrent virtual host requests")
        require_inaccessible: bool = Field(
            True,
            description="Only test virtual hosts that are not directly accessible (for discovering hidden content)",
        )
        wordcloud_check: bool = Field(False, description="Enable check using scan-wide wordcloud data on target host")
        report_interesting_default_content: bool = Field(True, description="Report interesting default content")

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

    async def _response_similarity(self, text_a, text_b, normalization_filter=None):
        """
        Compute simhash similarity between two response bodies.
        Runs in the CPU thread pool: simhash work is short and the input is
        truncated to ~3KB inside compute_simhash, so the process-pool overhead
        (pickle + IPC + worker lifecycle) costs more than the work itself.
        """
        kwargs = {}
        if normalization_filter is not None:
            kwargs["normalization_filter"] = normalization_filter
        hash_a = await self.helpers.run_in_executor_cpu(compute_simhash, text_a, **kwargs)
        hash_b = await self.helpers.run_in_executor_cpu(compute_simhash, text_b, **kwargs)
        return self.helpers.simhash.similarity(hash_a, hash_b)

    def _get_basehost(self, event):
        """Get the basehost and subdomain from the event"""
        basehost = self.helpers.parent_domain(event.parsed_url.hostname)
        if not basehost:
            raise ValueError(f"No parent domain found for {event.parsed_url.hostname}")
        subdomain = event.parsed_url.hostname.removesuffix(basehost).rstrip(".")
        return basehost, subdomain

    async def _get_baseline_response(self, event, normalized_url, host_ip):
        """Get baseline response for a host using the appropriate method (HTTPS SNI or HTTP Host header)"""
        is_https = event.parsed_url.scheme == "https"
        host = event.parsed_url.netloc

        if is_https:
            port = event.parsed_url.port or 443
            baseline_response = await self.helpers.request(
                url=f"https://{host}:{port}/",
                resolve_ip=host_ip,
            )
        else:
            baseline_response = await self.helpers.request(
                url=normalized_url,
                headers={"Host": host},
                resolve_ip=host_ip,
            )

        return baseline_response

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
                subdomain = ""
            else:
                basehost, subdomain = self._get_basehost(event)

            is_https = event.parsed_url.scheme == "https"

            if not event.resolved_hosts:
                self.debug(f"HANDLE EVENT METHOD: No resolved hosts for {normalized_url}, skipping virtual host check")
                return None

            # resolved_hosts can contain CNAME targets (hostnames) alongside A/AAAA records;
            # we need a real IP to pin the TCP connection via blasthttp's resolve_ip.
            ip_candidates = [str(h) for h in event.resolved_hosts if self.helpers.is_ip(h)]
            if not ip_candidates:
                self.debug(
                    f"HANDLE EVENT METHOD: resolved_hosts for {normalized_url} contains no IPs (only CNAMEs?), skipping virtual host check"
                )
                return None
            host_ip = ip_candidates[0]

            baseline_response = await self._get_baseline_response(event, normalized_url, host_ip)
            if not baseline_response:
                self.warning(f"Failed to get baseline response for {normalized_url}")
                return None

            if not await self._wildcard_canary_check(scheme, host, event, host_ip, baseline_response):
                self.verbose(
                    f"WILDCARD CHECK FAILED in handle_event: Skipping {normalized_url} - failed virtual host wildcard check"
                )
                return None
            else:
                self.verbose(f"WILDCARD CHECK PASSED in handle_event: Proceeding with {normalized_url}")

            # Phase 1: Main virtual host bruteforce
            if self.config.get("subdomain_brute", True):
                self.verbose(f"=== Starting subdomain brute-force on {normalized_url} ===")
                await self._run_virtualhost_phase(
                    "Target host Subdomain Brute-force",
                    normalized_url,
                    basehost,
                    host_ip,
                    is_https,
                    event,
                    "subdomain",
                )

            # only run mutations if there is an actual subdomain (to mutate)
            if subdomain:
                # Phase 2: Check existing host for mutations
                if self.config.get("mutation_check", True):
                    self.verbose(f"=== Starting mutations check on {normalized_url} ===")
                    await self._run_virtualhost_phase(
                        "Mutations on target host",
                        normalized_url,
                        basehost,
                        host_ip,
                        is_https,
                        event,
                        "mutation",
                        wordlist=self.mutations_check(subdomain),
                    )

            # Phase 3: Special virtual host list
            if self.config.get("special_hosts", False):
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
            if self.config.get("certificate_sans", False):
                self.verbose(f"=== Starting certificate SAN analysis on {normalized_url} ===")
                if is_https:
                    subject_alternate_names = await self._analyze_subject_alternate_names(normalized_url)
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
        """Analyze subject alternate names from certificate via blasthttp cert_info"""
        parsed = urlparse(url)
        host = parsed.netloc

        response = await self.helpers.request(url=url)
        if not response or not response.cert_info:
            self.debug(f"No certificate data available for {url}")
            return []

        subject_alt_names = []
        try:
            for san in response.cert_info.sans:
                self.debug(f"Found SAN: {san}")
                if san != host and san not in subject_alt_names:
                    subject_alt_names.append(san)
        except Exception as e:
            self.warning(f"Error parsing certificate for {url}: {e}")

        self.debug(
            f"Found {len(subject_alt_names)} Subject Alternative Names: {subject_alt_names} (besides original target host {host})"
        )
        return subject_alt_names

    async def _report_interesting_default_content(self, event, canary_hostname, host_ip, canary_response):
        discovery_method = "Interesting Default Content (from intentionally-incorrect canary host)"
        # Build URL with explicit authority to avoid double-port issues
        authority = (
            f"{event.parsed_url.hostname}:{event.parsed_url.port}"
            if event.parsed_url.port is not None
            else event.parsed_url.hostname
        )
        # Use the explicit canary hostname used in the wildcard request (works for HTTP Host and HTTPS SNI)
        canary_host = (canary_hostname or "").split(":")[0]
        # peer_ip is the actual TCP peer the response came from — ground truth, not a
        # guess from resolved_hosts. Falls back to the pinned host_ip if peer_ip is empty.
        response_ip = getattr(canary_response, "peer_ip", None) or host_ip
        virtualhost_dict = {
            "host": str(event.host),
            "url": f"{event.parsed_url.scheme}://{authority}/",
            "virtual_host": canary_host,
            "description": self._build_description(discovery_method, canary_response, True, response_ip),
            "ip": response_ip,
        }

        await self.emit_event(
            virtualhost_dict,
            "VIRTUAL_HOST",
            parent=event,
            tags=["virtual-host"],
            context=f"{{module}} discovered virtual host via {discovery_method} for {event.url} and found {{event.type}}: {canary_host}",
        )

        # Emit HTTP_RESPONSE event with the canary response data
        headers = dict(canary_response.headers) if canary_response.headers else {}

        # Get the scheme from the actual probe URL
        probe_url = str(canary_response.url) if canary_response.url else ""
        parsed_probe_url = urlparse(probe_url)
        actual_scheme = parsed_probe_url.scheme if parsed_probe_url.scheme else "http"

        body = canary_response.text or ""
        http_response_data = {
            "input": canary_host,
            "url": f"{actual_scheme}://{canary_host}/",
            "method": "GET",
            "status_code": canary_response.status_code,
            "content_length": len(body),
            "body": body,
            "header": headers,
            "raw_header": "",
        }

        # Include location header for redirect handling
        location = headers.get("location", "")
        if location:
            http_response_data["location"] = location

        http_response_event = await self.emit_event(
            http_response_data,
            "HTTP_RESPONSE",
            parent=event,
            tags=["virtual-host"],
            context=f"{{module}} discovered virtual host via {discovery_method} for {event.url} and found {{event.type}}: {canary_host}",
        )
        # Set scope distance to match parent's scope distance for HTTP_RESPONSE events
        if http_response_event:
            http_response_event.scope_distance = event.scope_distance

    def _get_canary_random_host(self, host, basehost, mode="subdomain"):
        """Generate a random host for the canary"""
        rng = random.Random(host)

        if mode == "mutation":
            random_prefix = "".join(rng.choice(string.ascii_lowercase) for i in range(4))
            canary_host = f"{random_prefix}-{host}"
        elif mode == "subdomain":
            canary_host = "".join(rng.choice(string.ascii_lowercase) for i in range(self.CANARY_LENGTH)) + basehost
        elif mode == "random_append":
            random_suffix = "".join(rng.choice(string.ascii_lowercase) for i in range(4))
            canary_host = f"{host.split('.')[0]}{random_suffix}.{'.'.join(host.split('.')[1:])}"
        elif mode == "random":
            random_host = "".join(rng.choice(string.ascii_lowercase) for i in range(self.CANARY_LENGTH))
            canary_host = f"{random_host}.com"
        else:
            raise ValueError(f"Invalid canary mode: {mode}")

        return canary_host

    async def _get_canary_response(self, normalized_url, basehost, host_ip, is_https, mode="subdomain"):
        """Setup canary response for comparison using the appropriate technique. Returns canary response or None on failure."""

        parsed = urlparse(normalized_url)
        # Use hostname without port to avoid duplicating port in canary host
        host = parsed.hostname or (parsed.netloc.split(":")[0] if ":" in parsed.netloc else parsed.netloc)

        # Seed RNG with domain to get consistent canary hosts for same domain
        canary_host = self._get_canary_random_host(host, basehost, mode)

        # Get canary response
        if is_https:
            port = parsed.port or 443
            canary_response = await self.helpers.request(
                url=f"https://{canary_host}:{port}/",
                resolve_ip=host_ip,
            )
        else:
            canary_response = await self.helpers.request(
                url=normalized_url,
                headers={"Host": canary_host},
                resolve_ip=host_ip,
            )

        return canary_response

    async def _is_host_accessible(self, url):
        """
        Check if a URL is already accessible via direct HTTP request.
        Returns True if the host is accessible (and should be skipped), False otherwise.
        """
        response = await self.helpers.request(url=url)
        if response and response.status_code > 0:
            return True
        return False

    async def _wildcard_canary_check(self, probe_scheme, probe_host, event, host_ip, probe_response):
        """Change one char in probe_host and test - if responses are similar, it's probably a wildcard"""

        # Extract hostname and port separately to avoid corrupting the port portion
        original_hostname = event.parsed_url.hostname or ""
        original_port = event.parsed_url.port

        # Try to mutate the first alphabetic character in the hostname
        modified_hostname = None
        for i, char in enumerate(original_hostname):
            if char.isalpha():
                new_char = "z" if char != "z" else "a"
                modified_hostname = original_hostname[:i] + new_char + original_hostname[i + 1 :]
                break

        if modified_hostname is None:
            # Fallback: generate random hostname of similar length (hostname-only)
            modified_hostname = "".join(
                random.choice(string.ascii_lowercase) for _ in range(len(original_hostname) or 12)
            )

        # Build modified host strings for each protocol
        https_modified_host_for_sni = modified_hostname
        http_modified_host_for_header = f"{modified_hostname}:{original_port}" if original_port else modified_hostname

        # Test modified host
        if probe_scheme == "https":
            port = event.parsed_url.port or 443
            # Log the canary URL for the wildcard SNI test
            self.debug(
                f"CANARY URL: https://{https_modified_host_for_sni}:{port}/ [phase=wildcard-check, mode=single-char-mutation]"
            )
            wildcard_canary_response = await self.helpers.request(
                url=f"https://{https_modified_host_for_sni}:{port}/",
                resolve_ip=host_ip,
            )
        else:
            # Log the canary URL for the wildcard Host header test
            http_port = event.parsed_url.port or 80
            self.debug(
                f"CANARY URL: {probe_scheme}://{http_modified_host_for_header if ':' in http_modified_host_for_header else f'{http_modified_host_for_header}:{http_port}'}/ [phase=wildcard-check, mode=single-char-mutation]"
            )
            wildcard_canary_response = await self.helpers.request(
                url=f"{probe_scheme}://{event.parsed_url.netloc}/",
                headers={"Host": http_modified_host_for_header},
                resolve_ip=host_ip,
            )

        if not wildcard_canary_response or wildcard_canary_response.status_code == 0:
            self.debug(
                f"Wildcard check: {http_modified_host_for_header} failed to respond, assuming {probe_host} is valid"
            )
            return True  # Modified failed, original probably valid

        # If HTTP status codes differ, consider this a pass (not wildcard)
        if probe_response.status_code != wildcard_canary_response.status_code:
            self.debug(
                f"WILDCARD CHECK OK (status mismatch): {probe_host} ({probe_response.status_code}) vs {http_modified_host_for_header} ({wildcard_canary_response.status_code})"
            )
            if (
                self.config.get("report_interesting_default_content", True)
                and wildcard_canary_response.status_code == 200
                and len(wildcard_canary_response.text or "") > 40
            ):
                canary_hostname = (
                    https_modified_host_for_sni if probe_scheme == "https" else http_modified_host_for_header
                )
                await self._report_interesting_default_content(
                    event, canary_hostname, host_ip, wildcard_canary_response
                )
            return True

        similarity = await self._response_similarity(probe_response.text or "", wildcard_canary_response.text or "")

        # Compare original probe response with modified response

        result = similarity <= self.SIMILARITY_THRESHOLD

        if not result:
            self.debug(
                f"WILDCARD DETECTED: {probe_host} vs {http_modified_host_for_header} similarity: {similarity:.3f} (threshold: {self.SIMILARITY_THRESHOLD}) -> FAIL (wildcard detected)"
            )
        else:
            self.debug(
                f"WILDCARD CHECK OK: {probe_host} vs {http_modified_host_for_header} similarity: {similarity:.3f} (threshold: {self.SIMILARITY_THRESHOLD}) -> PASS (not wildcard)"
            )
            if (
                self.config.get("report_interesting_default_content", True)
                and wildcard_canary_response.status_code == 200
                and len(wildcard_canary_response.text or "") > 40
            ):
                canary_hostname = (
                    https_modified_host_for_sni if probe_scheme == "https" else http_modified_host_for_header
                )
                await self._report_interesting_default_content(
                    event, canary_hostname, host_ip, wildcard_canary_response
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
    ):
        """Helper method to run a virtual host discovery phase and optionally mutations"""

        canary_response = await self._get_canary_response(
            normalized_url, basehost, host_ip, is_https, mode=canary_mode
        )

        if not canary_response:
            self.debug(f"Failed to get canary response for {normalized_url}, skipping virtual host detection")
            return []

        results = await self._test_virtualhost_candidates(
            discovery_method,
            normalized_url,
            basehost,
            event,
            canary_response,
            canary_mode,
            wordlist,
            skip_dns_host,
        )

        # Emit all valid results
        for virtual_host_data in results:
            # Emit VIRTUAL_HOST event
            await self.emit_event(
                virtual_host_data["virtualhost_dict"],
                "VIRTUAL_HOST",
                parent=event,
                tags=["virtual-host"],
                context=f"{{module}} discovered virtual host via {virtual_host_data['discovery_method']} for {event.url} and found {{event.type}}: {virtual_host_data['probe_host']} (similarity: {virtual_host_data['similarity']:.2%})",
            )

            # Emit HTTP_RESPONSE event with the probe response data
            probe_resp = virtual_host_data["probe_response"]
            headers = dict(probe_resp.headers) if probe_resp.headers else {}

            # Get the scheme from the actual probe URL
            probe_url = str(probe_resp.url) if probe_resp.url else ""
            parsed_probe_url = urlparse(probe_url)
            actual_scheme = parsed_probe_url.scheme if parsed_probe_url.scheme else "http"

            body = probe_resp.text or ""
            http_response_data = {
                "input": virtual_host_data["probe_host"],
                "url": f"{actual_scheme}://{virtual_host_data['probe_host']}/",
                "method": "GET",
                "status_code": probe_resp.status_code,
                "content_length": len(body),
                "body": body,
                "header": headers,
                "raw_header": "",
            }

            # Include location header for redirect handling
            location = headers.get("location", "")
            if location:
                http_response_data["location"] = location

            http_response_event = await self.emit_event(
                http_response_data,
                "HTTP_RESPONSE",
                parent=event,
                tags=["virtual-host"],
                context=f"{{module}} discovered virtual host via {virtual_host_data['discovery_method']} for {event.url} and found {{event.type}}: {virtual_host_data['probe_host']}",
            )
            # Set scope distance to match parent's scope distance for HTTP_RESPONSE events
            if http_response_event:
                http_response_event.scope_distance = event.scope_distance

            # Emit DNS_NAME_UNVERIFIED event if needed
            if virtual_host_data["skip_dns_host"] is False:
                await self.emit_event(
                    virtual_host_data["virtualhost_dict"]["virtual_host"],
                    "DNS_NAME_UNVERIFIED",
                    parent=event,
                    tags=["virtual-host"],
                    context=f"{{module}} discovered virtual host via {virtual_host_data['discovery_method']} for {event.url} and found {{event.type}}: {{event.data}}",
                )

    async def _test_virtualhost_candidates(
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
                # Wordlist entries are subdomain prefixes - append basehost
                probe_host = f"{word}.{basehost}"

            else:
                # No basehost - use as-is
                probe_host = word

            # Skip if this would be the same as the original host
            if probe_host == baseline_host:
                continue

            candidates_to_check.append(probe_host)

        self.debug(f"Loaded {len(candidates_to_check)} candidates from wordlist for {discovery_method}")

        # filter out non-IP entries (e.g. CNAME targets) — we can't connect-pin via hostname
        host_ips = [str(h) for h in event.resolved_hosts if self.helpers.is_ip(h)]
        total_tests = len(candidates_to_check) * len(host_ips)

        self.verbose(
            f"Initiating {total_tests} virtual host tests ({len(candidates_to_check)} candidates × {len(host_ips)} IPs) with max {self.max_concurrent} concurrent requests"
        )

        # Collect all virtual host results before emitting
        virtual_host_results = []

        # Process results as they complete with concurrency control
        try:
            # Build coroutines on-demand without wrapper
            coroutines = (
                self._test_virtualhost(
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
                for host_ip in host_ips
                for probe_host in candidates_to_check
            )

            async for completed in self.helpers.as_completed(coroutines, self.max_concurrent):
                try:
                    result = await completed
                except Exception as e:
                    if getattr(self.scan, "stopping", False) or getattr(self.scan, "aborting", False):
                        self.debug(f"Exception during shutdown (suppressed): {e}")
                        break
                    self.debug(f"Exception in virtualhost test (skipping this test): {e}")
                    continue
                if result:  # Only append non-None results
                    virtual_host_results.append(result)
                    self.debug(
                        f"ADDED RESULT {len(virtual_host_results)}: {result['probe_host']} (similarity: {result['similarity']:.3f}) [Status: {result['status_code']} | Size: {result['content_length']} bytes]"
                    )

                    if len(virtual_host_results) >= self.MAX_RESULTS_FLOOD_PROTECTION:
                        self.warning(
                            f"RESULT FLOOD DETECTED: found {len(virtual_host_results)} virtual hosts (limit: {self.MAX_RESULTS_FLOOD_PROTECTION}), likely false positives - discarding results"
                        )
                        return []

        except Exception as e:
            if getattr(self.scan, "stopping", False) or getattr(self.scan, "aborting", False):
                self.debug(f"Exception in as_completed during shutdown (suppressed): {e}")
                return []
            self.warning(f"Exception in as_completed, stopping all tests: {e}")
            return []

        # Return results for emission at _run_virtualhost_phase level
        return virtual_host_results

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
            probe_response = await self.helpers.request(
                url=f"https://{probe_host}:{port}/",
                resolve_ip=host_ip,
            )
        else:
            port = event.parsed_url.port or 80
            probe_response = await self.helpers.request(
                url=normalized_url,
                headers={"Host": probe_host},
                resolve_ip=host_ip,
            )

        if not probe_response or not probe_response.text:
            protocol = "HTTPS" if is_https else "HTTP"
            self.debug(f"{protocol} probe failed for {probe_host} on ip {host_ip} - no response or empty data")
            return None

        similarity = await self.analyze_response(probe_host, probe_response, canary_response, event)
        if similarity is None:
            return None

        # Different from canary = possibly real virtual host, similar to canary = probably junk
        if similarity > self.SIMILARITY_THRESHOLD:
            self.debug(
                f"REJECTING {probe_host}: similarity {similarity:.3f} > threshold {self.SIMILARITY_THRESHOLD} (too similar to canary)"
            )
            return None
        else:
            self.verbose(
                f"POTENTIAL VIRTUALHOST {probe_host} sim={similarity:.3f} "
                f"probe: {probe_response.status_code} | {len(probe_response.text or '')}B | {probe_response.url} ; "
                f"canary: {canary_response.status_code} | {len(canary_response.text or '')}B | {canary_response.url}"
            )

        # Re-verify canary consistency before emission
        if not await self._verify_canary_consistency(
            canary_response, canary_mode, normalized_url, is_https, basehost, host_ip
        ):
            self.verbose(
                f"CANARY CHANGED: Rejecting {probe_host}. Original canary had code {canary_response.status_code} and response data of length {len(canary_response.text or '')}"
            )
            return None
        # Canary is consistent, proceed

        probe_url = f"{event.parsed_url.scheme}://{probe_host}:{port}/"

        # Check for keyword-based virtual host wildcards
        if not await self._verify_canary_keyword(probe_response, probe_url, is_https, basehost, host_ip):
            return None

        # Don't emit if this would be the same as the original netloc
        if probe_host == event.parsed_url.netloc:
            self.verbose(f"Skipping emit for virtual host {probe_host} - is the same as the original netloc")
            return None

        # Check if this virtual host is externally accessible
        port = event.parsed_url.port or (443 if is_https else 80)

        is_externally_accessible = await self._is_host_accessible(probe_url)

        # peer_ip is the actual TCP peer the response came from — ground truth, not a
        # guess from resolved_hosts. Falls back to the pinned host_ip if peer_ip is empty.
        response_ip = getattr(probe_response, "peer_ip", None) or host_ip
        virtualhost_dict = {
            "host": str(event.host),
            "url": normalized_url,
            "virtual_host": probe_host,
            "description": self._build_description(
                discovery_method, probe_response, is_externally_accessible, response_ip
            ),
            "ip": response_ip,
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
            "status_code": probe_response.status_code,
            "content_length": len(probe_response.text or ""),
            "probe_response": probe_response,
        }

    async def analyze_response(self, probe_host, probe_response, canary_response, event):
        probe_status = probe_response.status_code
        canary_status = canary_response.status_code

        # Check for invalid/no response - skip processing
        if probe_status == 0 or not probe_response.text:
            self.debug(f"SKIPPING {probe_host} - no valid HTTP response (status: {probe_status})")
            return None

        if probe_status == 400:
            self.debug(f"SKIPPING {probe_host} - got 400 Bad Request")
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
            redirect_url = probe_response.headers.get("location", "") if probe_response.headers else ""
            if redirect_url and str(event.parsed_url.netloc) in redirect_url:
                self.debug(f"SKIPPING {probe_host} - redirects back to original domain {event.parsed_url.netloc}")
                return None

        if any(waf_string in (probe_response.text or "") for waf_string in self.waf_strings):
            self.debug(f"SKIPPING {probe_host} - got WAF response")
            return None

        # Calculate content similarity to canary (junk response)
        # Use probe hostname for normalization to remove hostname reflection differences

        similarity = await self._response_similarity(
            probe_response.text or "",
            canary_response.text or "",
            normalization_filter=probe_host,
        )

        if similarity <= self.SIMILARITY_THRESHOLD:
            self.verbose(
                f"POTENTIAL MATCH: {probe_host} vs canary - similarity: {similarity:.3f} (threshold: {self.SIMILARITY_THRESHOLD}), probe status: {probe_status}, canary status: {canary_status}"
            )

        return similarity

    async def _verify_canary_keyword(self, original_response, probe_url, is_https, basehost, host_ip):
        """Perform last-minute check on the canary for keyword-based virtual host wildcards"""

        try:
            keyword_canary_response = await self._get_canary_response(
                probe_url, basehost, host_ip, is_https, mode="random_append"
            )
        except Exception as e:
            self.warning(f"Canary verification failed: {e}")
            return False

        if not keyword_canary_response:
            return False

        # If we get the exact same content after altering the hostname, keyword based virtual host routing is likely being used
        if (keyword_canary_response.text or "") == (original_response.text or ""):
            self.verbose(
                f"Intentionally wrong hostname has a canary too similar to the original. Using probe url: {probe_url} - response data is exactly the same"
            )
            return False

        similarity = await self._response_similarity(original_response.text or "", keyword_canary_response.text or "")

        if similarity >= self.SIMILARITY_THRESHOLD:
            self.verbose(
                f"Intentionally wrong hostname has a canary too similar to the original. Using probe url: {probe_url} - similarity: {similarity:.3f} above threshold {self.SIMILARITY_THRESHOLD} - Original: {original_response.status_code} ({len(original_response.text or '')} bytes), Current: {keyword_canary_response.status_code} ({len(keyword_canary_response.text or '')} bytes)"
            )
            return False
        return True

    async def _verify_canary_consistency(
        self, original_canary_response, canary_mode, normalized_url, is_https, basehost, host_ip
    ):
        """Perform last-minute check on the canary for consistency"""

        # Re-run the same canary test as we did initially
        try:
            consistency_canary_response = await self._get_canary_response(
                normalized_url, basehost, host_ip, is_https, mode=canary_mode
            )
        except Exception as e:
            self.warning(f"Canary verification failed: {e}")
            return False

        if not consistency_canary_response:
            return False

        # Check if HTTP codes are different first (hard failure)
        if original_canary_response.status_code != consistency_canary_response.status_code:
            self.verbose(
                f"CANARY HTTP CODE CHANGED for {normalized_url} - Original: {original_canary_response.status_code} ({len(original_canary_response.text or '')} bytes), Current: {consistency_canary_response.status_code} ({len(consistency_canary_response.text or '')} bytes)"
            )
            return False

        # if response data is exactly the same, we're good
        if (original_canary_response.text or "") == (consistency_canary_response.text or ""):
            return True

        # Fallback - use similarity comparison for response data (allows slight differences)
        similarity = await self._response_similarity(
            original_canary_response.text or "", consistency_canary_response.text or ""
        )
        if similarity < self.SIMILARITY_THRESHOLD:
            self.verbose(
                f"CANARY SIMILARITY CHANGED for {normalized_url} - similarity: {similarity:.3f} below threshold {self.SIMILARITY_THRESHOLD} - Original: {original_canary_response.status_code} ({len(original_canary_response.text or '')} bytes), Current: {consistency_canary_response.status_code} ({len(consistency_canary_response.text or '')} bytes)"
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
        http_code = probe_response.status_code if probe_response else "N/A"
        response_size = len(probe_response.text or "") if probe_response else 0

        description = f"Discovery Technique: [{discovery_string}], Discovered Content: [Status Code: {http_code}]"

        # Add title if available
        title = self._extract_title(probe_response.text or "" if probe_response else "")
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
        self.verbose(" === Starting Finish() Wordcloud check === ")
        if not self.config.get("wordcloud_check", False):
            self.debug("FINISH METHOD: Wordcloud check is disabled, skipping finish phase")
            return

        if not self.helpers.word_cloud.keys():
            self.verbose("FINISH METHOD: No wordcloud data available for finish phase")
            return

        # Filter wordcloud words: no dots, reasonable length limit
        all_wordcloud_words = list(self.helpers.word_cloud.keys())
        filtered_words = []
        for word in all_wordcloud_words:
            # Filter out words with dots (likely full domains)
            if "." in word:
                continue
            # Filter out very long words (likely noise)
            if len(word) > 15:
                continue
            # Filter out very short words (likely noise)
            if len(word) < 2:
                continue
            filtered_words.append(word)

        tempfile = self.helpers.tempfile(filtered_words, pipe=False)
        self.debug(
            f"FINISH METHOD: Starting wordcloud check on {len(self.scanned_hosts)} hosts using {len(filtered_words)} filtered words from wordcloud"
        )

        for host, event in self.scanned_hosts.items():
            if host not in self.wordcloud_tried_hosts:
                host_parsed_url = urlparse(host)

                if self.config.get("force_basehost"):
                    basehost = self.config.get("force_basehost")
                else:
                    basehost, subdomain = self._get_basehost(event)

                # Get fresh canary and original response for this host
                is_https = host_parsed_url.scheme == "https"

                if not event.resolved_hosts:
                    self.debug(f"FINISH METHOD: No resolved hosts for {host}, skipping wordcloud check")
                    continue

                host_ip = str(next(iter(event.resolved_hosts)))

                self.verbose(f"FINISH METHOD: Starting wildcard check for {host}")
                baseline_response = await self._get_baseline_response(event, host, host_ip)
                if not await self._wildcard_canary_check(
                    host_parsed_url.scheme, host_parsed_url.netloc, event, host_ip, baseline_response
                ):
                    self.debug(
                        f"WILDCARD CHECK FAILED in finish: Skipping {host} in wordcloud phase - failed virtual host wildcard check"
                    )
                    self.wordcloud_tried_hosts.add(host)  # Mark as tried to avoid retrying
                    continue
                else:
                    self.debug(f"WILDCARD CHECK PASSED in finish: Proceeding with wordcloud mutations for {host}")

                await self._run_virtualhost_phase(
                    "Target host wordcloud mutations",
                    host,
                    basehost,
                    host_ip,
                    is_https,
                    event,
                    "subdomain",
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
            self.debug(f"Not processing URL {event.url} because it's behind a WAF or CDN, and that's pointless")
            return False
        return True
