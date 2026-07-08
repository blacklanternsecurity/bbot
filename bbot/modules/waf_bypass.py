from radixtarget import RadixTarget
from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field
from bbot.core.helpers.simhash import compute_simhash


class waf_bypass(BaseModule):
    """
    Module to detect WAF bypasses by finding direct IP access to WAF-protected content.

    Overview:
        Throughout the scan, we collect:
        1. WAF-protected domains (identified by CloudFlare/Imperva tags) and their SimHash content fingerprints
        2. All domain->IP mappings from DNS resolution of URL events
        3. Cloud IPs separately tracked via "cloud-ip" tags

        In finish(), we test if WAF-protected content can be accessed directly via IPs from non-protected domains.
        Optionally, it explores IP neighbors within the same ASN to find additional bypass candidates.
    """

    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["active", "safe", "web-heavy"]

    class Config(BaseModuleConfig):
        similarity_threshold: float = Field(0.90, description="Similarity threshold for content matching")
        search_ip_neighbors: bool = Field(True, description="Also check IP neighbors of the target domain")
        neighbor_cidr: int = Field(
            24,
            ge=24,
            le=31,
            description="CIDR mask (24-31) used for neighbor enumeration when search_ip_neighbors is true",
        )

    meta = {
        "description": "Detects potential WAF bypasses",
        "author": "@liquidsec",
        "created_date": "2025-09-26",
    }

    async def setup(self):
        # Track protected domains and their potential bypass CIDRs
        self.protected_domains = {}  # {domain: event} - track protected domains and store their parent events
        self.domain_ip_map = {}  # {full_domain: set(ips)} - track all IPs for each domain
        self.content_fingerprints = {}  # {url: {simhash, http_code}}
        self.similarity_threshold = self.config.get("similarity_threshold", 0.90)
        self.search_ip_neighbors = self.config.get("search_ip_neighbors", True)
        self.neighbor_cidr = int(self.config.get("neighbor_cidr", 24))

        # Keep track of (protected_domain, ip) pairs we have already attempted to bypass
        self.attempted_bypass_pairs = set()
        # Keep track of any IPs that came from hosts that are "cloud-ips"
        self.cloud_ips = set()
        return True

    async def filter_event(self, event):
        if "endpoint" in event.tags:
            return False, "WAF bypass module only considers directory URLs"
        return True

    async def handle_event(self, event):
        domain = str(event.host)
        url = event.url

        # Store the IPs that each domain (that came from a URL event) resolves to. We have to resolve ourself, since normal BBOT DNS resolution doesn't keep ALL the IPs
        domain_dns_response = await self.helpers.dns.resolve(domain)
        if domain_dns_response:
            if domain not in self.domain_ip_map:
                self.domain_ip_map[domain] = set()
            for ip in domain_dns_response:
                ip_str = str(ip)
                # Validate that this is actually an IP address before storing
                if self.helpers.is_ip(ip_str):
                    self.domain_ip_map[domain].add(ip_str)
                    self.debug(f"Mapped domain {domain} to IP {ip_str}")
                    if "cloud-ip" in event.tags:
                        self.cloud_ips.add(ip_str)
                        self.debug(f"Added cloud-ip {ip_str} to cloud_ips")
                else:
                    self.warning(f"DNS resolution for {domain} returned non-IP result: {ip_str}")
        else:
            self.warning(f"DNS resolution failed for {domain}")

        # Detect WAF/CDN protection based on tags
        provider_name = None
        if "cdn-cloudflare" in event.tags or "waf-cloudflare" in event.tags:
            provider_name = "CloudFlare"
        elif "cdn-imperva" in event.tags:
            provider_name = "Imperva"

        is_protected = provider_name is not None

        if is_protected:
            self.debug(f"{provider_name} protection detected via tags: {event.tags}")
            # Save the full domain and event for WAF-protected URLs, this is necessary to find the appropriate parent event later in .finish()
            self.protected_domains[domain] = event
            self.debug(f"Found {provider_name}-protected domain: {domain}")

            response = await self.get_url_content(url)
            if not response:
                self.debug(f"Failed to get response from protected URL {url}")
                return

            if not response.text:
                self.debug(f"Failed to get content from protected URL {url}")
                return

            # Store a "simhash" (fuzzy hash) of the response data for later comparison
            simhash = await self.helpers.run_in_executor_mp(compute_simhash, response.text)

            self.content_fingerprints[url] = {
                "simhash": simhash,
                "http_code": response.status_code,
            }
            self.debug(f"Stored simhash of response from {url} (content length: {len(response.text)})")

    async def get_url_content(self, url, ip=None):
        """Helper function to fetch content from a URL, optionally through specific IP"""
        try:
            kwargs = {"url": url}
            if ip:
                self.debug(f"Fetching with resolve_ip={ip} for {url}")
                kwargs["resolve_ip"] = str(ip)
            response = await self.helpers.request(**kwargs)
            if not response:
                self.debug(f"No content returned for {url}" + (f" via IP {ip}" if ip else ""))
                return None
            if response.status_code not in [200, 301, 302, 500]:
                self.debug(f"Rejected {url} - Status: {response.status_code} (not in allowed list)")
                return None
            return response
        except Exception as e:
            self.debug(f"Error fetching content from {url}: {str(e)}")
        return None

    async def check_ip(self, ip, source_domain, protected_domain, source_event):
        matching_url = next(
            (url for url in self.content_fingerprints if self.helpers.urlparse(url).hostname == protected_domain),
            None,
        )

        if not matching_url:
            self.debug(f"No matching URL found for {protected_domain} in stored fingerprints")
            return None

        original_response = self.content_fingerprints[matching_url]

        self.verbose(f"Bypass attempt: {protected_domain} via {ip} from {source_domain}")

        bypass_response = await self.get_url_content(matching_url, ip)
        if not bypass_response:
            self.debug(f"Failed to get content through IP {ip} for URL {matching_url}")
            return None

        bypass_simhash = await self.helpers.run_in_executor_mp(compute_simhash, bypass_response.text or "")

        if original_response["http_code"] != bypass_response.status_code:
            self.debug(f"Ignoring code difference {original_response['http_code']} != {bypass_response.status_code}")
            return None

        is_redirect = bypass_response.status_code in (301, 302)

        similarity = self.helpers.simhash.similarity(original_response["simhash"], bypass_simhash)

        # For redirects, require exact match (1.0), otherwise use configured threshold
        required_threshold = 1.0 if is_redirect else self.similarity_threshold
        return (matching_url, ip, similarity, source_event) if similarity >= required_threshold else None

    async def finish(self):
        self.verbose(f"Found {len(self.protected_domains)} Protected Domains")

        confirmed_bypasses = []  # [(protected_url, matching_ip, similarity)]
        ip_bypass_candidates = {}  # {ip: domain}
        waf_ips = set()

        # First collect all the WAF-protected DOMAINS we've seen
        for protected_domain in self.protected_domains:
            if protected_domain in self.domain_ip_map:
                waf_ips.update(self.domain_ip_map[protected_domain])

        # Then collect all the non-WAF-protected IPs we've seen
        for domain, ips in self.domain_ip_map.items():
            self.debug(f"Checking IP {ips} from domain {domain}")
            if domain not in self.protected_domains:  # If it's not a protected domain
                for ip in ips:
                    # Validate that this is actually an IP address before processing
                    if not self.helpers.is_ip(ip):
                        self.warning(f"Skipping non-IP address '{ip}' found in domain_ip_map for {domain}")
                        continue

                    if ip not in waf_ips:  # And IP isn't a known WAF IP
                        ip_bypass_candidates[ip] = domain
                        self.debug(f"Added potential bypass IP {ip} from domain {domain}")

                        # if we have IP neighbors searching enabled, and the IP isn't a cloud IP, we can add the IP neighbors to our list of potential bypasses
                        if self.search_ip_neighbors and ip not in self.cloud_ips:
                            import ipaddress

                            # Get the ASN data for the IP - used later to keep brute force from crossing ASN boundaries
                            asn_data = await self.helpers.asn.ip_to_subnets(str(ip))
                            if asn_data:
                                # Build a radix tree of the ASN subnets for the IP
                                asn_subnets_tree = RadixTarget()
                                for subnet in asn_data["subnets"]:
                                    asn_subnets_tree.insert(subnet)

                                # Generate a network based on the neighbor_cidr option
                                neighbor_net = ipaddress.ip_network(f"{ip}/{self.neighbor_cidr}", strict=False)
                                for neighbor_ip in neighbor_net.hosts():
                                    neighbor_ip_str = str(neighbor_ip)
                                    # Don't add the neighbor IP if its: ip we started with, a waf ip, or already in the list
                                    if (
                                        neighbor_ip_str == ip
                                        or neighbor_ip_str in waf_ips
                                        or neighbor_ip_str in ip_bypass_candidates
                                    ):
                                        continue

                                    # make sure we aren't crossing an ASN boundary with our neighbor exploration
                                    if asn_subnets_tree.search(neighbor_ip_str):
                                        self.debug(
                                            f"Added Neighbor IP ({ip} -> {neighbor_ip_str}) as potential bypass IP derived from {domain}"
                                        )
                                        ip_bypass_candidates[neighbor_ip_str] = domain
                    else:
                        self.debug(f"IP {ip} is in WAF IPS so we don't check as potential bypass")

        self.verbose(f"\nFound {len(ip_bypass_candidates)} non-WAF IPs to check")

        coros = []
        new_pairs_count = 0

        for protected_domain, source_event in self.protected_domains.items():
            for ip, src in ip_bypass_candidates.items():
                combo = (protected_domain, ip)
                if combo in self.attempted_bypass_pairs:
                    continue
                self.attempted_bypass_pairs.add(combo)
                new_pairs_count += 1
                self.debug(f"Checking {ip} for {protected_domain} from {src}")
                coros.append(self.check_ip(ip, src, protected_domain, source_event))

        self.verbose(
            f"Checking {new_pairs_count} new bypass pairs (total attempted: {len(self.attempted_bypass_pairs)})..."
        )

        self.debug(f"about to start {len(coros)} coroutines")
        async for completed in self.helpers.as_completed(coros):
            result = await completed
            if result:
                confirmed_bypasses.append(result)

        if confirmed_bypasses:
            # Aggregate by URL and similarity
            agg = {}
            for matching_url, ip, similarity, src_evt in confirmed_bypasses:
                rec = agg.setdefault((matching_url, round(similarity, 2)), {"ips": [], "event": src_evt})
                rec["ips"].append(ip)

            for (matching_url, sim_key), data in agg.items():
                ip_list = data["ips"]
                ip_list_str = ", ".join(sorted(set(ip_list)))
                await self.emit_event(
                    {
                        "severity": "MEDIUM",
                        "confidence": "CONFIRMED",
                        "name": "WAF Bypass",
                        "url": matching_url,
                        "description": f"WAF Bypass Confirmed - Direct IPs: {ip_list_str} for {matching_url}. Similarity {sim_key:.2%}",
                    },
                    "FINDING",
                    data["event"],
                )
