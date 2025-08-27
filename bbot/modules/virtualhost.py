import base64
from urllib.parse import urlparse

from bbot.modules.ffuf import ffuf


class virtualhost(ffuf):
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
    }
    options_desc = {
        "wordlist": "Wordlist containing subdomains",
        "force_basehost": "Use a custom base host (e.g. evilcorp.com) instead of the default behavior of using the current URL",
        "lines": "take only the first N lines from the wordlist when finding directories",
    }

    deps_common = ["ffuf"]
    banned_characters = {" ", "."}

    in_scope_only = True

    async def setup(self):
        self.scanned_hosts = {}
        self.wordcloud_tried_hosts = set()
        return await super().setup()

    async def handle_event(self, event):
        if not self.helpers.is_ip(event.host) or self.config.get("force_basehost"):
            host = f"{event.parsed_url.scheme}://{event.parsed_url.netloc}"
            if host in self.scanned_hosts:
                return
            else:
                self.scanned_hosts[host] = event

            # subdomain virtual host check
            if self.config.get("force_basehost"):
                basehost = self.config.get("force_basehost")
            else:
                basehost = self.helpers.parent_domain(event.parsed_url.netloc)
            self.debug(f"Using basehost: {basehost}")

            # Phase 1: Main virtual host bruteforce
            await self._run_virtualhost_phase(
                "Main virtual host bruteforce", host, f".{basehost}", event, with_mutations=True
            )

            # Phase 2: Check existing host for mutations
            await self._run_virtualhost_phase(
                "Checking for virtual host mutations on main host",
                host,
                f".{basehost}",
                event,
                wordlist=self.mutations_check(event.parsed_url.netloc.split(".")[0]),
            )

            # Phase 3: Special virtual host list
            await self._run_virtualhost_phase(
                "Checking special virtual host list",
                host,
                "",
                event,
                wordlist=self.helpers.tempfile(self.special_virtualhost_list, pipe=False),
                skip_dns_host=True,
            )

    async def _setup_canary(self, host, event, host_ip, is_https):
        """Setup canary response for comparison using the appropriate technique. Returns canary fingerprint or None on failure."""
        try:
            from urllib.parse import urlparse
            import random
            import string

            parsed = urlparse(host)
            baseline_host = parsed.netloc

            # Generate random junk hostname for canary
            canary_host = (
                "".join(random.choice(string.ascii_lowercase) for i in range(self.CANARY_LENGTH)) + f".{baseline_host}"
            )

            if is_https:
                self.debug(f"Testing canary host via SNI: {canary_host}")

                port = parsed.port or 443

                # Get canary response using SNI
                canary_response = await self.helpers.web.curl(
                    url=f"https://{canary_host}:{port}{parsed.path or '/'}",
                    resolve={"host": canary_host, "port": port, "ip": host_ip},
                )

                if not canary_response:
                    self.debug(f"First SNI canary attempt failed for {host}, retrying...")
                    canary_response = await self.helpers.web.curl(
                        url=f"https://{canary_host}:{port}{parsed.path or '/'}",
                        resolve={"host": canary_host, "port": port, "ip": host_ip},
                    )
            else:
                self.debug(f"Testing canary host via Host header: {canary_host}")

                # For HTTP, use Host header manipulation
                canary_response = await self.helpers.web.curl(url=host, headers={"Host": canary_host})

                if not canary_response:
                    self.debug(f"First HTTP canary attempt failed for {host}, retrying...")
                    canary_response = await self.helpers.web.curl(url=host, headers={"Host": canary_host})

            if not canary_response:
                self.warning(f"Failed to get canary response for {host} after retry, skipping virtual host detection")
                return None

            # Create content fingerprint of canary response
            canary_fingerprint = self.get_content_fingerprint(canary_response["response_data"])
            if not canary_fingerprint:
                self.warning(f"Failed to create canary fingerprint for {host}, skipping virtual host detection")
                return None

            self.debug(
                f"Canary response: {len(canary_response['response_data'])} bytes, fingerprint: {len(canary_fingerprint)} bytes"
            )
            return canary_fingerprint

        except (KeyError, ValueError) as e:
            self.debug(f"Error parsing host or creating canary for {host}: {e}")
            return None
        except Exception as e:
            self.debug(f"Unexpected error getting canary for {host}: {e}")
            return None

    async def _run_virtualhost_phase(
        self, phase_name, host, basehost, event, wordlist=None, skip_dns_host=False, with_mutations=False
    ):
        """Helper method to run a virtual host discovery phase and optionally mutations"""
        self.verbose(phase_name)

        async for virtualhost in self.curl_virtualhost(host, basehost, event, wordlist, skip_dns_host):
            if with_mutations:
                self.verbose(f"Starting mutations check for {virtualhost}")
                async for _ in self.curl_virtualhost(
                    host, basehost, event, wordlist=self.mutations_check(virtualhost)
                ):
                    pass

    async def curl_virtualhost(self, host, basehost, event, wordlist=None, skip_dns_host=False):
        if wordlist is None:
            wordlist = self.tempfile

        # Get baseline host for comparison and determine scheme
        from urllib.parse import urlparse

        parsed = urlparse(host)
        baseline_host = parsed.netloc
        is_https = parsed.scheme == "https"

        # Collect all words for concurrent processing
        wordlist_words = []
        for word in self.helpers.read_file(wordlist):
            word = word.strip()
            if not word:
                continue
            # Construct virtual host header
            if basehost:
                test_host = f"{word}{basehost}"
            else:
                test_host = word

            # Skip if this would be the same as the original host
            if test_host == baseline_host:
                continue

            wordlist_words.append((word, test_host))

        # Create concurrent tasks for all virtual host tests - method varies by scheme
        import asyncio

        tasks = []

        host_ips = event.resolved_hosts

        for host_ip in host_ips:
            # Get canary response to compare against (junk host that shouldn't exist)
            canary_fingerprint = await self._setup_canary(host, event, host_ip, is_https)
            if not canary_fingerprint:
                return

            for word, test_host in wordlist_words:
                if is_https:
                    task = asyncio.create_task(
                        self._test_https_virtualhost(
                            host, test_host, word, basehost, event, canary_fingerprint, skip_dns_host, host_ip, parsed
                        )
                    )
                else:
                    task = asyncio.create_task(
                        self._test_http_virtualhost(
                            host, test_host, word, basehost, event, canary_fingerprint, skip_dns_host, host_ip
                        )
                    )
                tasks.append(task)

            method = "SNI" if is_https else "Host header"
            self.verbose(f"Testing {len(tasks)} virtual hosts concurrently using {method}...")

            # Process results as they complete
            found_hosts = []
            async for completed in self.helpers.as_completed(tasks):
                result = await completed
                if result:
                    found_hosts.append(result)
                    yield result

            self.verbose(f"Found {len(found_hosts)} virtual hosts")

    async def _test_http_virtualhost(
        self, host, test_host, word, basehost, event, canary_fingerprint, skip_dns_host, host_ip
    ):
        """
        Test a single virtual host candidate using HTTP Host header
        Returns the virtual host name if detected, None otherwise
        """
        try:
            # Make request with custom Host header using curl with status code
            curl_result = await self.helpers.web.curl(
                url=host, headers={"Host": test_host}, resolve={"host": test_host, "port": 80, "ip": host_ip}
            )

            if not curl_result:
                return None

            # Check for 421 Misdirected Request - clear signal that virtual host doesn't exist
            if curl_result["http_code"] == 421:
                self.critical(f"SKIPPING {test_host} - got 421 Misdirected Request (virtual host not configured)")
                return None

            response = curl_result["response_data"]

            # Create content fingerprint for comparison
            response_fingerprint = self.get_content_fingerprint(response)
            if not response_fingerprint:
                return None

            # Calculate content similarity to canary (junk response)
            similarity = self.get_content_similarity(canary_fingerprint, response_fingerprint)

            self.debug(
                f"Testing URL: {host} | Virtual Host: {test_host} | Response: {len(response)} bytes | Similarity to canary: {similarity:.3f}"
            )

            # If similarity is low (different from junk response), it's likely a valid virtual host
            # Different from canary = real virtual host, similar to canary = also junk
            if similarity > self.SIMILARITY_THRESHOLD:
                return None

            virtualhost_dict = {
                "host": str(event.host),
                "url": host,
                "virtual_host": word,
                "technique": "Host header brute-force",
                "ip": host_ip,
            }

            # Don't emit if this would be the same as the original netloc
            if f"{virtualhost_dict['virtual_host']}{basehost}" != event.parsed_url.netloc:
                await self.emit_event(
                    virtualhost_dict,
                    "VIRTUAL_HOST",
                    parent=event,
                    context=f"{{module}} discovered virtual host via Host header brute-force for {event.data} and found {{event.type}}: {word} (similarity: {similarity:.2%})",
                )

                if skip_dns_host is False:
                    await self.emit_event(
                        f"{virtualhost_dict['virtual_host']}{basehost}",
                        "DNS_NAME",
                        parent=event,
                        tags=["virtual-host"],
                        context=f"{{module}} discovered virtual host via Host header brute-force for {event.data} and found {{event.type}}: {{event.data}}",
                    )

                return word

        except Exception as e:
            self.debug(f"Error testing virtual host {word}: {e}")
            return None

    async def _test_https_virtualhost(
        self, host, test_host, word, basehost, event, canary_fingerprint, skip_dns_host, host_ip, parsed
    ):
        """
        Test a single virtual host candidate using HTTPS SNI with curl --resolve
        Returns the virtual host name if detected, None otherwise
        """
        try:
            # Extract host IP from event's resolved_hosts (use first one like httpx would)
            if not event.resolved_hosts:
                self.debug(f"No resolved hosts available for {parsed.hostname} for SNI testing")
                return None

            port = parsed.port or 443

            # Use curl --resolve to map the test_host to the actual IP
            # This forces SNI to use test_host while connecting to the real IP
            curl_result = await self.helpers.web.curl(
                url=f"https://{test_host}:{port}{parsed.path or '/'}",
                resolve={"host": test_host, "port": port, "ip": host_ip},
            )

            if not curl_result:
                return None

            # Check for 421 Misdirected Request - clear signal that virtual host doesn't exist
            if curl_result["http_code"] == 421:
                self.debug(f"SKIPPING {test_host} - got 421 Misdirected Request (SNI not configured)")
                return None

            response = curl_result["response_data"]

            # Create content fingerprint for comparison
            response_fingerprint = self.get_content_fingerprint(response)
            if not response_fingerprint:
                return None

            # Calculate content similarity to canary (junk response)
            similarity = self.get_content_similarity(canary_fingerprint, response_fingerprint)

            # Critical debug info
            self.debug(
                f"Testing URL: {host} | SNI: {test_host} | Response: {len(response)} bytes | Similarity to canary: {similarity:.3f} | IP: {host_ip}"
            )

            # If similarity is low (different from junk response), it's likely a valid virtual host
            if similarity > self.SIMILARITY_THRESHOLD:
                self.debug(
                    f"SKIPPING {test_host} - too similar to canary ({similarity:.2%} >= {self.SIMILARITY_THRESHOLD:.2%})"
                )
                return None

            virtualhost_dict = {
                "host": str(event.host),
                "url": host,
                "virtual_host": word,
                "technique": "SNI brute-force",
                "ip": host_ip,
            }

            # Don't emit if this would be the same as the original netloc
            if f"{virtualhost_dict['virtual_host']}{basehost}" != event.parsed_url.netloc:
                await self.emit_event(
                    virtualhost_dict,
                    "VIRTUAL_HOST",
                    parent=event,
                    context=f"{{module}} discovered virtual host via SNI brute-force for {event.data} and found {{event.type}}: {word} (similarity: {similarity:.2%})",
                )

                if skip_dns_host is False:
                    await self.emit_event(
                        f"{virtualhost_dict['virtual_host']}{basehost}",
                        "DNS_NAME",
                        parent=event,
                        tags=["virtual-host"],
                        context=f"{{module}} discovered virtual host via SNI brute-force for {event.data} and found {{event.type}}: {{event.data}}",
                    )

                return word

        except Exception as e:
            self.debug(f"Error testing virtual host {word} via SNI: {e}")
            return None

    def get_content_fingerprint(self, content):
        """Extract a representative fingerprint from content (from waf_bypass)"""
        if not content:
            return None

        # Take 3 samples of 500 chars each from start, middle and end
        # This gives us enough context for comparison while reducing storage
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
            for i in ["", "-"]:
                mutations_list.append(i.join(mutation))
        mutations_list_file = self.helpers.tempfile(mutations_list, pipe=False)
        return mutations_list_file

    async def finish(self):
        # check existing hosts with wordcloud
        tempfile = self.helpers.tempfile(list(self.helpers.word_cloud.keys()), pipe=False)

        for host, event in self.scanned_hosts.items():
            if host not in self.wordcloud_tried_hosts:
                event.parsed_url = urlparse(host)

                if self.config.get("force_basehost"):
                    basehost = self.config.get("force_basehost")
                else:
                    basehost = self.helpers.parent_domain(event.parsed_url.netloc)

                await self._run_virtualhost_phase(
                    "Checking main host with wordcloud", host, f".{basehost}", event, wordlist=tempfile
                )

                self.wordcloud_tried_hosts.add(host)
