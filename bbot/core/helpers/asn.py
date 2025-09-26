import ipaddress
import logging
import asyncio
from radixtarget.tree.ip import IPRadixTree
from cachetools import LRUCache

log = logging.getLogger("bbot.core.helpers.asn")


class ASNHelper:
    asndb_ip_url = "https://asndb.api.bbot.io/v1/ip/"
    asndb_asn_url = "https://asndb.api.bbot.io/v1/asn/"

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        # IP radix trees (authoritative store) – IPv4 and IPv6
        self._tree4: IPRadixTree = IPRadixTree()
        self._tree6: IPRadixTree = IPRadixTree()
        # LRU caches with reasonable limits to prevent unbounded memory growth
        self._subnet_to_asn_cache: LRUCache = LRUCache(maxsize=10000)  # Cache subnet -> ASN mappings
        # ASN cache (ASN ID -> data mapping)
        self._asn_to_data_cache: LRUCache = LRUCache(maxsize=5000)  # Cache ASN records

    # Default record used when no ASN data can be found
    UNKNOWN_ASN = {
        "asn": "0",
        "subnets": [],
        "name": "unknown",
        "description": "unknown",
        "country": "unknown",
    }

    async def _request_with_retry(self, url, max_retries=10):
        log.critical(f"ASN API request: {url}")
        """Make request with retry for 429 responses using Retry-After header."""
        for attempt in range(max_retries + 1):
            response = await self.parent_helper.request(url, timeout=15)
            if response is None or getattr(response, "status_code", 0) == 200:
                log.debug(f"ASN API request successful, status code: {getattr(response, 'status_code', 0)}")
                return response

            elif getattr(response, "status_code", 0) == 429:
                if attempt < max_retries:
                    attempt += 1
                    # Get retry-after header value, default to 1 second if not present
                    retry_after = getattr(response, "headers", {}).get("retry-after", "10")
                    delay = int(retry_after)
                    log.verbose(
                        f"ASN API rate limited, waiting {delay}s (retry-after: {retry_after}) (attempt {attempt})"
                    )
                    await asyncio.sleep(delay)
                else:
                    log.warning(f"ASN API gave up after {max_retries + 1} attempts due to repeatedrate limiting")
            elif getattr(response, "status_code", 0) == 404:
                log.debug(f"ASN API returned 404 for {url}")
                return None
            else:
                log.warning(
                    f"Got unexpected status code: {getattr(response, 'status_code', 0)} from ASN DB api ({url})"
                )
                return None

        return response

    async def _query_api(self, identifier, url_base, processor_method):
        """Common API query method that handles request/response pattern."""
        url = f"{url_base}{identifier}"
        response = await self._request_with_retry(url)
        if response is None:
            log.warning(f"ASN DB API: no response for {identifier}")
            return None

        status = getattr(response, "status_code", 0)
        if status != 200:
            return None

        try:
            raw = response.json()
        except Exception as e:
            log.warning(f"ASN DB API: JSON decode error for {identifier}: {e}")
            return None

        if isinstance(raw, dict):
            return processor_method(raw, identifier)

        log.warning(f"ASN DB API: returned unexpected format for {identifier}: {raw}")
        return None

    def _build_asn_record(self, raw, subnets):
        """Build standardized ASN record from API response."""
        return {
            "asn": str(raw.get("asn", "")),
            "subnets": subnets,
            "name": raw.get("asn_name") or "",
            "description": raw.get("org") or "",
            "country": raw.get("country") or "",
        }

    async def asn_to_subnets(self, asn):
        """Return subnets for *asn* using cached subnet ranges where possible."""
        # Handle both int and str inputs
        if isinstance(asn, int):
            asn_int = asn
        else:
            try:
                asn_int = int(str(asn.lower()).lstrip("as"))
            except ValueError:
                log.warning(f"Invalid ASN format: {asn}")
                return self.UNKNOWN_ASN

        cached = self._cache_lookup_asn(asn_int)
        if cached is not None:
            log.debug(f"cache HIT for asn: {asn}")
            return cached

        log.debug(f"cache MISS for asn: {asn}")
        asn_data = await self._query_api_asn(asn_int)
        if asn_data:
            self._cache_store_asn(asn_data, asn_int)
            return asn_data
        return self.UNKNOWN_ASN

    async def ip_to_subnets(self, ip: str):
        """Return ASN info for *ip* using cached subnet ranges where possible."""

        ip_str = str(ipaddress.ip_address(ip))
        cached = self._cache_lookup_ip(ip_str)
        if cached is not None:
            log.debug(f"cache HIT for ip: {ip_str}")
            return cached or self.UNKNOWN_ASN

        log.debug(f"cache MISS for ip: {ip_str}")
        asn_data = await self._query_api_ip(ip_str)
        if asn_data:
            self._cache_store_ip(asn_data)
            return asn_data
        return self.UNKNOWN_ASN

    async def _query_api_ip(self, ip: str):
        """Query ASN DB API for IP address information."""
        return await self._query_api(ip, self.asndb_ip_url, self._process_ip_response)

    def _process_ip_response(self, raw, ip):
        """Process IP lookup response from ASN DB API."""
        subnets = raw.get("subnets", [])
        # API returns subnets as array, but handle string case for safety
        if isinstance(subnets, str):
            subnets = [subnets]
        if not subnets:
            subnets = [f"{ip}/32"]
        return self._build_asn_record(raw, subnets)

    async def _query_api_asn(self, asn: str):
        """Query ASN DB API for ASN information."""
        return await self._query_api(asn, self.asndb_asn_url, self._process_asn_response)

    def _process_asn_response(self, raw, asn):
        """Process ASN lookup response from ASN DB API."""
        subnets = raw.get("subnets", [])
        # API returns subnets as array, but handle string case for safety
        if isinstance(subnets, str):
            subnets = [subnets]
        return self._build_asn_record(raw, subnets)

    def _cache_store_asn(self, asn_record, asn_id: int):
        """Cache ASN data by ASN ID"""
        self._asn_to_data_cache[asn_id] = asn_record
        log.debug(f"ASN cache ADD {asn_id} -> {asn_record.get('asn', '?') if asn_record else '?'}")

    def _cache_lookup_asn(self, asn_id: int):
        """Lookup cached ASN data by ASN ID"""
        return self._asn_to_data_cache.get(asn_id)

    def _cache_store_ip(self, asn_record):
        if not (self._tree4 or self._tree6):
            return
        subnets = asn_record.get("subnets") or []
        if isinstance(subnets, str):
            subnets = [subnets]
        for p in subnets:
            try:
                net = ipaddress.ip_network(p, strict=False)
            except ValueError:
                continue
            tree = self._tree4 if net.version == 4 else self._tree6
            tree.insert(str(net), data=asn_record)
            self._subnet_to_asn_cache[str(net)] = asn_record
            log.debug(f"IP cache ADD {net} -> {asn_record.get('asn', '?')}")

    def _cache_lookup_ip(self, ip: str):
        ip_obj = ipaddress.ip_address(ip)
        tree = self._tree4 if ip_obj.version == 4 else self._tree6
        node = tree.get_node(ip)
        if node and getattr(node, "data", None):
            return node.data
        return None
