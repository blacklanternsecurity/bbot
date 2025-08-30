from urllib.parse import urlparse

from bbot.modules.base import BaseModule


class virtualhost(BaseModule):
    watched_events = ["URL"]
    produced_events = ["VIRTUAL_HOST", "DNS_NAME"]
    flags = ["active", "aggressive", "slow", "deadly"]
    meta = {"description": "Fuzz for virtual hosts", "created_date": "2022-05-02", "author": "@liquidsec"}

    # Constants for magic values
    SIMILARITY_THRESHOLD = 0.95
    CANARY_LENGTH = 12
    CONTENT_FINGERPRINT_SIZE = 500

    special_virtualhost_list = ["127.0.0.1", "localhost", "host.docker.internal"]
    options = {
        "wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
        "force_basehost": "",
        "lines": 5000,
        "subdomain_brute": True,
        "mutation_check": True,
        "special_hosts": True,
        "certificate_sans": True,
        "max_concurrent_requests": 100,
    }
    options_desc = {
        "wordlist": "Wordlist containing subdomains",
        "force_basehost": "Use a custom base host (e.g. evilcorp.com) instead of the default behavior of using the current URL",
        "lines": "take only the first N lines from the wordlist when finding directories",
        "subdomain_brute": "Enable subdomain brute-force on target host",
        "mutation_check": "Enable mutations check on target host",
        "special_hosts": "Enable testing of special virtual host list (localhost, etc.)",
        "certificate_sans": "Enable extraction and testing of Subject Alternative Names from certificates",
        "max_concurrent_requests": "Maximum number of concurrent virtual host requests",
    }

    in_scope_only = True

    async def setup(self):
        self.max_concurrent = self.config.get("max_concurrent_requests", 100)
        self.scanned_hosts = {}
        self.wordcloud_tried_hosts = set()
        self.wordlist = await self.helpers.wordlist(self.config.get("wordlist"), lines=self.config.get("lines", 5000))
        return await super().setup()

    async def handle_event(self, event):
        if not self.helpers.is_ip(event.host) or self.config.get("force_basehost"):
            host = f"{event.parsed_url.scheme}://{event.parsed_url.netloc}"

            # since we normalize the URL to the host level,
            if host in self.scanned_hosts:
                return
            else:
                self.scanned_hosts[host] = event

            if self.config.get("force_basehost"):
                basehost = self.config.get("force_basehost")
            else:
                basehost = self.helpers.parent_domain(event.parsed_url.netloc)
            self.debug(f"Using basehost: {basehost}")

            is_https = event.parsed_url.scheme == "https"

            # We request the URL in order to get the SSL cert data (for https urls) and to provide a backup for the canary data if the "nonsense" canary fails
            original_response = await self.helpers.web.curl(url=event.data)
            if not original_response:
                self.debug(f"Failed to get original response for {event.data}, skipping virtual host detection")
                return

            # Try to get a canary fingerprint using a nonsense subdomain. It will be compared against brute-forced requests to determine if the request found a real virtual host.
            # If the canary fails, we fall back to using the 'original response' as the canary.
            canary_status, canary_fingerprint = await self._get_canary_fingerprint(
                host, original_response, next(iter(event.resolved_hosts)), is_https
            )
            if not canary_fingerprint:
                self.debug(f"Failed to setup canary for {host}, skipping virtual host detection")
                return

            # Phase 1: Main virtual host bruteforce
            if self.config.get("subdomain_brute", True):
                self.verbose(f"=== Starting subdomain brute-force on {host} ===")
                await self._run_virtualhost_phase(
                    "Target host SubdomainBrute-force",
                    host,
                    f".{basehost}",
                    event,
                    canary_status,
                    canary_fingerprint,
                    original_response,
                    with_mutations=True,
                )

            # Phase 2: Check existing host for mutations
            if self.config.get("mutation_check", True):
                self.verbose(f"=== Starting mutations check on {host} ===")
                await self._run_virtualhost_phase(
                    "Mutations on target host",
                    host,
                    f".{basehost}",
                    event,
                    canary_status,
                    canary_fingerprint,
                    original_response,
                    wordlist=self.mutations_check(event.parsed_url.netloc.split(".")[0]),
                )

            # Phase 3: Special virtual host list
            if self.config.get("special_hosts", True):
                self.verbose(f"=== Starting special virtual hosts check on {host} ===")
                await self._run_virtualhost_phase(
                    "Special virtual host list",
                    host,
                    "",
                    event,
                    canary_status,
                    canary_fingerprint,
                    original_response,
                    wordlist=self.helpers.tempfile(self.special_virtualhost_list, pipe=False),
                    skip_dns_host=True,
                )

            # Phase 4: Obtain subject alternate names from certicate and analyze them
            if self.config.get("certificate_sans", True):
                self.verbose(f"=== Starting certificate SAN analysis on {host} ===")
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
                            host,
                            "",
                            event,
                            canary_status,
                            canary_fingerprint,
                            original_response,
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

    async def _get_canary_fingerprint(self, host, original_response, host_ip, is_https):
        """Setup canary response for comparison using the appropriate technique. Returns canary fingerprint or None on failure."""

        from urllib.parse import urlparse
        import random
        import string

        parsed = urlparse(host)
        baseline_host = parsed.netloc

        # Generate random junk hostname for canary
        canary_host = (
            "".join(random.choice(string.ascii_lowercase) for i in range(self.CANARY_LENGTH)) + f".{baseline_host}"
        )

        # Get canary response
        if is_https:
            port = parsed.port or 443
            canary_response = await self.helpers.web.curl(
                url=f"https://{canary_host}:{port}{parsed.path or '/'}",
                resolve={"host": canary_host, "port": port, "ip": host_ip},
            )
        else:
            canary_response = await self.helpers.web.curl(url=host, headers={"Host": canary_host})

        if not canary_response or len(canary_response["response_data"]) == 0:
            self.debug("Didn't get a response, or got an empty response. Falling back to real host")
            canary_status = original_response["http_code"]
            canary_fingerprint = self.get_content_fingerprint(original_response["response_data"])
            self.debug(
                f"Using original response as canary - Status: {canary_status}, Content length: {len(original_response['response_data'])}"
            )
            return canary_status, canary_fingerprint
        else:
            canary_status = canary_response["http_code"]
            canary_fingerprint = self.get_content_fingerprint(canary_response["response_data"])
            if not canary_fingerprint:
                self.debug(f"Failed to create canary fingerprint for {host}")
                return None, None
        return canary_status, canary_fingerprint

    async def _run_virtualhost_phase(
        self,
        discovery_method,
        host,
        basehost,
        event,
        canary_status,
        canary_fingerprint,
        original_response,
        wordlist=None,
        skip_dns_host=False,
        with_mutations=False,
    ):
        """Helper method to run a virtual host discovery phase and optionally mutations"""

        virtual_hosts_found = []
        async for virtualhost in self.curl_virtualhost(
            discovery_method,
            host,
            basehost,
            event,
            canary_status,
            canary_fingerprint,
            original_response,
            wordlist,
            skip_dns_host,
        ):
            virtual_hosts_found.append(virtualhost)
            if with_mutations:
                async for mutation in self.curl_virtualhost(
                    discovery_method,
                    host,
                    basehost,
                    event,
                    canary_status,
                    canary_fingerprint,
                    original_response,
                    wordlist=self.mutations_check(virtualhost),
                ):
                    pass  # emit of any VIRTUAL_HOST events is handled inside curl_virtualhost
            pass  # emit of any VIRTUAL_HOST events is handled inside curl_virtualhost

    async def curl_virtualhost(
        self,
        discovery_method,
        host,
        basehost,
        event,
        canary_status,
        canary_fingerprint,
        original_response,
        wordlist=None,
        skip_dns_host=False,
    ):
        if wordlist is None:
            wordlist = self.wordlist

        # Get baseline host for comparison and determine scheme from event
        baseline_host = event.parsed_url.netloc
        is_https = event.parsed_url.scheme == "https"

        # Collect all words for concurrent processing
        wordlist_words = []
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

            wordlist_words.append((word, probe_host))

        self.debug(f"Loaded {len(wordlist_words)} candidates from wordlist for {discovery_method}")

        coros = []
        host_ips = event.resolved_hosts

        for host_ip in host_ips:
            for word, probe_host in wordlist_words:
                if is_https:
                    technique = "SNI"
                    discovery_string = f"{discovery_method} ({technique})"
                    coro = self._test_https_virtualhost(
                        host,
                        probe_host,
                        basehost,
                        event,
                        canary_status,
                        canary_fingerprint,
                        skip_dns_host,
                        host_ip,
                        discovery_string,
                    )
                else:
                    technique = "Host header"
                    discovery_string = f"{discovery_method} ({technique})"
                    coro = self._test_http_virtualhost(
                        host,
                        probe_host,
                        basehost,
                        event,
                        canary_status,
                        canary_fingerprint,
                        skip_dns_host,
                        host_ip,
                        discovery_string,
                    )
                coros.append(coro)

            self.debug(
                f"Testing {len(coros)} virtual hosts with max {self.max_concurrent} concurrent requests using {discovery_string} against {len(host_ips)} IPs..."
            )

            # Process results as they complete with concurrency control
            async for completed in self.helpers.as_completed_with_limit(coros, self.max_concurrent):
                result = await completed
                if result:
                    yield result

    def analyze_response(self, probe_host, probe_result, canary_status, canary_fingerprint):
        probe_status = probe_result["http_code"]
        # Check for 421 Misdirected Request - clear signal that virtual host doesn't exist
        if probe_status == 421:
            self.debug(f"SKIPPING {probe_host} - got 421 Misdirected Request (SNI not configured)")
            return None

        # Check for 403 Forbidden - signal that the virtual host is rejected (unless we started with a 403)
        if probe_status == 403 and canary_status != 403:
            self.debug(f"SKIPPING {probe_host} - got 403 Forbidden when canary status was {canary_status}")
            return None

        # Create content fingerprint for comparison
        response_fingerprint = self.get_content_fingerprint(probe_result["response_data"])
        if not response_fingerprint:
            self.debug(f"SKIPPING {probe_host} - failed to create response fingerprint")
            return None

        # Calculate content similarity to canary (junk response)
        similarity = self.get_content_similarity(canary_fingerprint, response_fingerprint)
        return similarity

    async def _test_http_virtualhost(
        self,
        host,
        probe_host,
        basehost,
        event,
        canary_status,
        canary_fingerprint,
        skip_dns_host,
        host_ip,
        discovery_string,
    ):
        """
        Test a single virtual host candidate using HTTP Host header
        Returns the virtual host name if detected, None otherwise
        """

        # Make request with custom Host header using curl with status code
        probe_result = await self.helpers.web.curl(
            url=host,
            headers={"Host": probe_host},
            resolve={"host": probe_host, "port": event.port or 80, "ip": host_ip},
        )
        if not probe_result:
            return None

        similarity = self.analyze_response(probe_host, probe_result, canary_status, canary_fingerprint)
        if similarity is None:
            return None

        # Different from canary = possibly real virtual host, similar to canary = probably junk
        if similarity > self.SIMILARITY_THRESHOLD:
            return None

        virtualhost_dict = {
            "host": str(event.host),
            "url": host,
            "virtual_host": probe_host,
            "discovery_technique": discovery_string,
            "ip": host_ip,
        }

        # Don't emit if this would be the same as the original netloc
        if probe_host != event.parsed_url.netloc:
            await self.emit_event(
                virtualhost_dict,
                "VIRTUAL_HOST",
                parent=event,
                context=f"{{module}} discovered virtual host via Host header brute-force for {event.data} and found {{event.type}}: {probe_host} (similarity: {similarity:.2%})",
            )

            if skip_dns_host is False:
                await self.emit_event(
                    virtualhost_dict["virtual_host"],
                    "DNS_NAME",
                    parent=event,
                    tags=["virtual-host"],
                    context=f"{{module}} discovered virtual host via Host header brute-force for {event.data} and found {{event.type}}: {{event.data}}",
                )
        else:
            self.debug(f"SKIPPING {probe_host} - same as original netloc")

    async def _test_https_virtualhost(
        self,
        host,
        probe_host,
        basehost,
        event,
        canary_status,
        canary_fingerprint,
        skip_dns_host,
        host_ip,
        discovery_string,
    ):
        """
        Test a single virtual host candidate using HTTPS SNI with curl --resolve
        Returns the virtual host name if detected, None otherwise
        """
        # Extract host IP from event's resolved_hosts (use first one like httpx would)

        port = event.parsed_url.port or 443

        # Use curl --resolve to map the test_host to the actual IP
        # This forces SNI to use test_host while connecting to the real IP
        probe_result = await self.helpers.web.curl(
            url=f"https://{probe_host}:{port}{event.parsed_url.path or '/'}",
            resolve={"host": probe_host, "port": port, "ip": host_ip},
        )

        if not probe_result or probe_result["response_data"] == "":
            return None

        similarity = self.analyze_response(probe_host, probe_result, canary_status, canary_fingerprint)
        if similarity is None:
            return None

        # If similarity is low (different from junk response), it's likely a valid virtual host
        if similarity > self.SIMILARITY_THRESHOLD:
            return None

        virtualhost_dict = {
            "host": str(event.host),
            "url": host,
            "virtual_host": probe_host,
            "discovery_technique": discovery_string,
            "ip": host_ip,
        }

        # Don't emit if this would be the same as the original netloc
        if probe_host != event.parsed_url.netloc:
            await self.emit_event(
                virtualhost_dict,
                "VIRTUAL_HOST",
                parent=event,
                context=f"{{module}} discovered virtual host via SNI brute-force for {event.data} and found {{event.type}}: {probe_host} (similarity: {similarity:.2%})",
            )

            if skip_dns_host is False:
                await self.emit_event(
                    virtualhost_dict["virtual_host"],
                    "DNS_NAME",
                    parent=event,
                    tags=["virtual-host"],
                    context="{module} discovered a DNS name during the process of conducting a SNI brute-force for {event.data} and found {event.type}: {event.data}",
                )

        else:
            self.debug(f"SKIPPING {probe_host} - same as original netloc")

    def get_content_fingerprint(self, content):
        """Extract a representative fingerprint from content (from waf_bypass)"""
        if not content:
            return None

        content_len = len(content)
        if content_len <= 1500:
            return content  # If content is small enough, just return it all

        start = content[:500]
        mid_start = max(0, (content_len // 2) - 250)
        middle = content[mid_start : mid_start + 500]
        end = content[-500:]

        return start + middle + end

    def get_content_similarity(self, fingerprint1, fingerprint2):
        """Get similarity ratio between two content fingerprints (from waf_bypass)"""
        if not fingerprint1 or not fingerprint2:
            return 0.0
        from difflib import SequenceMatcher

        return SequenceMatcher(None, fingerprint1, fingerprint2).ratio()

    def mutations_check(self, virtualhost):
        mutations_list = []
        for mutation in self.helpers.word_cloud.mutations(virtualhost):
            mutations_list.extend(["".join(mutation), "-".join(mutation)])
        mutations_list_file = self.helpers.tempfile(mutations_list, pipe=False)
        return mutations_list_file

    async def finish(self):
        # check existing hosts with wordcloud
        if not self.helpers.word_cloud.keys():
            self.debug("No wordcloud data available for finish phase")
            return

        tempfile = self.helpers.tempfile(list(self.helpers.word_cloud.keys()), pipe=False)
        self.verbose(f"=== FINISH PHASE: Starting wordcloud mutations on {len(self.scanned_hosts)} hosts ===")
        self.debug(f"Using {len(list(self.helpers.word_cloud.keys()))} words from wordcloud")

        for host, event in self.scanned_hosts.items():
            if host not in self.wordcloud_tried_hosts:
                event.parsed_url = urlparse(host)

                if self.config.get("force_basehost"):
                    basehost = self.config.get("force_basehost")
                else:
                    basehost = self.helpers.parent_domain(event.parsed_url.netloc)

                # Get fresh canary and original response for this host
                is_https = event.parsed_url.scheme == "https"

                original_response = await self.helpers.web.curl(url=event.data)
                if not original_response:
                    self.debug(f"Failed to get original response for {event.data} in finish phase, skipping")
                    continue

                canary_status, canary_fingerprint = await self._get_canary_fingerprint(
                    host, original_response, next(iter(event.resolved_hosts)), is_https
                )
                if not canary_fingerprint:
                    self.debug(f"Failed to setup canary for {host} in finish phase, skipping")
                    continue

                await self._run_virtualhost_phase(
                    "Target host wordcloud mutations",
                    host,
                    f".{basehost}",
                    event,
                    canary_status,
                    canary_fingerprint,
                    original_response,
                    wordlist=tempfile,
                )
                self.wordcloud_tried_hosts.add(host)

    async def filter_event(self, event):
        if "cdn-cloudflare" in event.tags or "cdn-imperva" in event.tags or "cdn-akamai" in event.tags:
            self.debug(f"Not processing URL {event.data} because it's behind a WAF or CDN, and that's pointless")
            return False
        return True
