from bbot.modules.base import BaseModule
from bbot.modules.report.asn import asn
from difflib import SequenceMatcher
import asyncio
from bbot.core.helpers.web.ssl_context import ssl_context_noverify


class waf_bypass(BaseModule):
    """
    Module to detect WAF bypasses by finding domains not behind CloudFlare
    """
    watched_events = ["URL"]
    produced_events = ["VULNERABILITY"]
    options = {"similarity_threshold": 0.95, "search_ip_neighbors": True}
    options_desc = {"similarity_threshold": "Similarity threshold for content matching", "search_ip_neighbors": "Also check IP neighbors of qualified IPs"}
    flags = ["active", "safe", "web-thorough"]
    meta = {
        "description": "Detects potential WAF bypasses",
        "author": "@liquidsec",
    }

    async def setup(self):
        self.asn_helper = asn(self.scan)
        # Initialize required ASN attributes
        self.asn_helper.sources = ["bgpview", "ripe"]
        self.asn_helper.asn_counts = {}
        self.asn_helper.asn_cache = {}
        self.asn_helper.ripe_cache = {}
        
        # Track protected domains and their potential bypass CIDRs
        self.protected_domains = {}  # {domain: event} - store events for protected domains
        self.bypass_candidates = {}  # {base_domain: set(cidrs)}
        self.domain_ips = {}  # {full_domain: set(ips)}
        self.content_fingerprints = {}  # {full_url: fingerprint} store content samples for comparison
        self.similarity_threshold = self.config.get("similarity_threshold", 0.95)
        self.search_ip_neighbors = self.config.get("search_ip_neighbors", True)
        # Keep track of (protected_domain, ip) pairs we have already attempted to bypass
        self.attempted_bypass_pairs = set()
        # Keep track of any IPs that came from hosts that are "cloud-ips"
        self.cloud_ips = set()
        return True

    def get_content_fingerprint(self, content):
        """Extract a representative fingerprint from content"""
        if not content:
            return None
        
        # Take 3 samples of 500 chars each from start, middle and end
        # This gives us enough context for comparison while reducing storage
        content_len = len(content)
        if content_len <= 1500:
            return content  # If content is small enough, just return it all
            
        start = content[:500]
        mid_start = max(0, (content_len // 2) - 250)
        middle = content[mid_start:mid_start + 500]
        end = content[-500:]
        
        return start + middle + end

    def get_content_similarity(self, fingerprint1, fingerprint2):
        """Get similarity ratio between two content fingerprints"""
        if not fingerprint1 or not fingerprint2:
            return 0.0
        return SequenceMatcher(None, fingerprint1, fingerprint2).ratio()

    async def get_url_content(self, url, ip=None):
        """Helper function to fetch content from a URL, optionally through specific IP"""
        try:
            if ip:
                # Build resolve dict for curl helper
                host_tuple = self.helpers.extract_host(url)
                if not host_tuple[0]:
                    self.warning(f"Failed to extract host from URL: {url}")
                    return None
                host = host_tuple[0]

                # Determine port from scheme (default 443/80) or explicit port in URL
                try:
                    from urllib.parse import urlparse

                    parsed = urlparse(url)
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)
                except Exception:
                    port = 443  # safe default for https

                self.debug(
                    f"Fetching via curl with --resolve {host}:{port}:{ip} for {url}"
                )

                content = await self.helpers.web.curl(
                    url=url,
                    resolve={"host": host, "port": port, "ip": ip},
                )

                if content:
                    fingerprint = self.get_content_fingerprint(content)
                    self.debug(
                        f"Successfully fetched and fingerprinted content from {url} via IP {ip}"
                    )
                    return fingerprint
                else:
                    self.debug(f"curl returned no content for {url} via IP {ip}")
            else:
                response = await self.helpers.request(url, timeout=10)
                if response and response.status_code in [200, 301, 302, 500]:
                    content = response.text
                    fingerprint = self.get_content_fingerprint(content)
                    self.debug(
                        f"Successfully fetched and fingerprinted content from {url}"
                    )
                    return fingerprint
                else:
                    status = getattr(response, "status_code", "unknown")
                    self.debug(
                        f"Failed to fetch content from {url} - Status: {status}"
                    )
        except Exception as e:
            self.debug(f"Error fetching content from {url}: {str(e)}")
        return None

    async def handle_event(self, event):
        domain = str(event.host)
        base_domain = self.helpers.tldextract(domain).top_domain_under_public_suffix
        url = str(event.data)


        
        # Store IPs for every domain we see
        dns_response = await self.helpers.dns.resolve(domain)
        if dns_response:
            if domain not in self.domain_ips:
                self.domain_ips[domain] = set()
            for ip in dns_response:
                self.domain_ips[domain].add(str(ip))
                self.debug(f"Mapped domain {domain} to IP {ip}")
                if "cloud-ip" in event.tags:
                    self.cloud_ips.add(str(ip))
                    self.debug(f"Added cloud-ip {ip} to cloud_ips")
        else:
            self.warning(f" DNS resolution for {domain}")
        
        # Detect WAF/CDN protection based on tags
        provider_name = None
        if "cdn-cloudflare" in event.tags or "waf-cloudflare" in event.tags:
            provider_name = "CloudFlare"
        elif "cdn-imperva" in event.tags:
            provider_name = "Imperva"

        is_protected = provider_name is not None
        
        if is_protected:
            self.debug(f"{provider_name} protection detected via tags: {event.tags}")
            # Save the full domain and event for CloudFlare-protected URLs
            self.protected_domains[domain] = event
            self.debug(f"Found {provider_name}-protected domain: {domain}")
            
            # Fetch and store content
            content = await self.get_url_content(url)

            if not content:
                self.debug(f"Failed to get content from protected URL {url}")
                return

            self.content_fingerprints[url] = content
            self.debug(f"Stored content fingerprint from {url} (length: {len(content)})")

            # Get CIDRs from the base domain of the protected domain
            base_dns = await self.helpers.dns.resolve(base_domain)
            if base_dns:
                # Skip if base domain has same IPs as protected domain
                if set(str(ip) for ip in base_dns) == self.domain_ips.get(domain, set()):
                    self.debug(f"Base domain {base_domain} has same IPs as protected domain, skipping CIDR collection")
                else:
                    if base_domain not in self.bypass_candidates:
                        self.bypass_candidates[base_domain] = set()
                        self.debug(f"Created new CIDR set for {provider_name} base domain: {base_domain}")
                    
                    for ip in base_dns:
                        self.debug(f"Getting ASN info for IP {ip} from {provider_name} base domain {base_domain}")
                        asns, _ = await self.asn_helper.get_asn(str(ip))
                        if asns:
                            for asn_info in asns:
                               subnet = asn_info.get('subnet')
                               if subnet:
                                   self.bypass_candidates[base_domain].add(subnet)
                                   self.debug(f"Added CIDR {subnet} from {provider_name} base domain {base_domain} (ASN{asn_info.get('asn', 'Unknown')} - {asn_info.get('name', 'Unknown')})")
                        else:
                            self.warning(f"No ASN info found for IP {ip}")
            else:
                self.debug(f"WARNING: No DNS resolution for {provider_name} base domain {base_domain}")

        else:

            if "cdn-ip" in event.tags:
                self.debug("CDN IP detected, skipping CIDR collection")
                return

            # Collect CIDRs for non-CloudFlare domains
            if dns_response:
                if base_domain not in self.bypass_candidates:
                    self.bypass_candidates[base_domain] = set()
                    self.debug(f"Created new CIDR set for base domain: {base_domain}")
                
                for ip in dns_response:
                    self.debug(f"Getting ASN info for IP {ip} from non-CloudFlare domain {domain}")
                    asns, _ = await self.asn_helper.get_asn(str(ip))
                    if asns:
                        for asn_info in asns:
                            subnet = asn_info.get('subnet')
                            if subnet:
                                self.bypass_candidates[base_domain].add(subnet)
                                self.debug(f"Added CIDR {subnet} from non-CloudFlare domain {domain} (ASN{asn_info.get('asn', 'Unknown')} - {asn_info.get('name', 'Unknown')})")
                    else:
                        self.warning(f"No ASN info found for IP {ip}")


    async def filter_event(self, event):
        if "endpoint" in event.tags:
            return False, "WAF bypass module only considers directory URLs"
        return True


    async def check_ip(self, idx, ip, source_domain, protected_domain, total_ips):

        matching_url = next((url for url in self.content_fingerprints.keys() if protected_domain in url), None)
        if not matching_url:
            self.debug(f"No matching URL found for {protected_domain} in stored fingerprints")
            return None

        original_fingerprint = self.content_fingerprints.get(matching_url)
        if not original_fingerprint:
            self.debug(f"No original fingerprint for {matching_url}")
            return None

        self.verbose(
            f"Bypass attempt ({idx}/{total_ips}) {protected_domain} via {ip} (orig len {len(original_fingerprint)}) from {source_domain}"
        )

        bypass_fp = await self.get_url_content(matching_url, ip)
        if not bypass_fp:
            self.debug(
                f"({idx}/{total_ips}): Failed to get content through IP {ip} for URL {matching_url}"
            )
            return None

        similarity_raw = self.get_content_similarity(original_fingerprint, bypass_fp)
        similarity = round(similarity_raw, 2)  # store with limited precision
        return (matching_url, ip, similarity) if similarity_raw >= self.similarity_threshold else None

    async def finish(self):

        
        # Show protected domains as single-line debug message
        if not self.protected_domains:
            self.debug("Protected Domains: None found")
        else:
            protected_str = ", ".join(sorted(self.protected_domains.keys()))
            self.debug(f"Protected Domains: {protected_str}")
        
        # Show bypass candidates as single-line debug message
        if not self.bypass_candidates:
            self.debug("Bypass Candidates: None found")
        else:
            bypass_str = ", ".join(
                f"{base_domain}: [{', '.join(sorted(cidrs))}]" for base_domain, cidrs in sorted(self.bypass_candidates.items())
            )
            self.debug(f"Bypass Candidates: {bypass_str}")
        
        # Show domain to IP mappings as a single-line debug message
        if not self.domain_ips:
            self.debug("Domain to IP Mappings: None found")
        else:
            mapping_str = ", ".join(
                f"{domain}: [{', '.join(sorted(ips))}]" for domain, ips in sorted(self.domain_ips.items())
            )
            self.debug(f"Domain to IP Mappings: {mapping_str}")

        confirmed_bypasses = []  # [(protected_url, matching_ip, similarity)]
        
        # First, collect all non-CloudFlare IPs we've seen
        all_ips = {}  # {ip: domain}
        cloudflare_ips = set()
        
        
        # First collect CloudFlare IPs
        for protected_domain in self.protected_domains:
            if protected_domain in self.domain_ips:
                cloudflare_ips.update(self.domain_ips[protected_domain])
        
        # Then collect non-CloudFlare IPs
        for domain, ips in self.domain_ips.items():
            if domain not in self.protected_domains:  # If it's not a protected domain
                for ip in ips:
                    if ip not in cloudflare_ips:  # And IP isn't a known CloudFlare IP
                        all_ips[ip] = domain
                        self.debug(f"Added potential bypass IP {ip} from domain {domain}")

                        # If enabled, explore /28 neighbors within same ASN - skip if IP is a cloud-ip
                        if self.search_ip_neighbors and ip not in self.cloud_ips:
                            import ipaddress
                            orig_asns, _ = await self.asn_helper.get_asn(str(ip))
                            if orig_asns:
                                cidr28 = ipaddress.ip_network(f"{ip}/28", strict=False)
                                for neighbor_ip in cidr28.hosts():
                                    n_ip_str = str(neighbor_ip)
                                    if n_ip_str == ip or n_ip_str in cloudflare_ips or n_ip_str in all_ips:
                                        continue
                                    asns_neighbor, _ = await self.asn_helper.get_asn(n_ip_str)
                                    if not asns_neighbor:
                                        continue
                                    # Check if any ASN matches
                                    if any(a['asn'] == b['asn'] for a in orig_asns for b in asns_neighbor):
                                        all_ips[n_ip_str] = domain
                                        self.debug(f"Added Neighbor IP ({ip} -> {n_ip_str}) as potential bypass IP from {domain}")

        
        self.debug(f"\nFound {len(all_ips)} non-CloudFlare IPs to check: {all_ips}")
        
        # For each protected domain with progress display
        total_protected = len(self.protected_domains)
        total_ips = len(all_ips)


        tasks = []

        self.debug(f"attempted_bypass_pairs {len(self.attempted_bypass_pairs)} attempted bypass pairs")


        for idx, (protected_domain, source_event) in enumerate(self.protected_domains.items(), start=1):
            self.debug(f"\nAdding to tasks: {idx}/{total_protected}: {protected_domain}")
 
            # create tasks for every IP of this protected domain, marking attempts
            for ip_idx, (ip, src) in enumerate(all_ips.items(), start=1):
                combo = (protected_domain, ip)
                if combo in self.attempted_bypass_pairs:
                    continue
                self.attempted_bypass_pairs.add(combo)
                tasks.append(
                    asyncio.create_task(
                        self.check_ip(ip_idx, ip, src, protected_domain, total_ips)
                    )
                )

        self.debug(f"about to start {len(tasks)} tasks")
        async for completed in self.helpers.as_completed(tasks):
            result = await completed
            if result:
                confirmed_bypasses.append(result)
        
        if confirmed_bypasses:
            # Aggregate by URL and similarity
            agg = {}
            for matching_url, ip, similarity in confirmed_bypasses:
                rec = agg.setdefault((matching_url, similarity), [])
                rec.append(ip)

            for (matching_url, sim_key), ip_list in agg.items():
                ip_list_str = ", ".join(sorted(set(ip_list)))
                self.debug(
                    f"CONFIRMED BYPASS: {matching_url} via IPs [{ip_list_str}] (similarity {sim_key:.2%})"
                )
                await self.emit_event(
                    {
                        "severity": "MEDIUM",
                        "url": matching_url,
                        "description": f"WAF Bypass Confirmed - Direct IPs: {ip_list_str} for {matching_url}. Similarity {sim_key:.2%}",
                    },
                    "VULNERABILITY",
                    source_event,
                )