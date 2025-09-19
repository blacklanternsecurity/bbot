import ipaddress
import logging
import asyncio
from radixtarget.tree.ip import IPRadixTree

log = logging.getLogger("bbot.core.helpers.asn")


class ASNHelper:
    asndb_ip_url = "https://asndb.api.bbot.io/v1/ip/"
    asndb_asn_url = "https://asndb.api.bbot.io/v1/asn/"

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        # IP radix trees (authoritative store) – IPv4 and IPv6
        self._tree4: IPRadixTree = IPRadixTree()
        self._tree6: IPRadixTree = IPRadixTree()
        self._subnet_to_asn_cache: dict[str, list] = {}
        # ASN cache (ASN ID -> data mapping)
        self._asn_to_data_cache: dict[int, list] = {}

    # Default record used when no ASN data can be found
    UNKNOWN_ASN = {
        "asn": "UNKNOWN",
        "subnet": "0.0.0.0/32",
        "name": "unknown",
        "description": "unknown",
        "country": "",
    }

    async def _request_with_retry(self, url, max_retries=10):
        """Make request with retry for 429 responses."""
        for attempt in range(max_retries + 1):
            response = await self.parent_helper.request(url, timeout=15)
            if response is None or getattr(response, "status_code", 0) != 429:
                return response

            if attempt < max_retries:
                delay = min(2**attempt, 300)
                log.debug(f"ASN API rate limited, waiting {delay}s (attempt {attempt + 1})")
                await asyncio.sleep(delay)
            else:
                log.warning(f"ASN API gave up after {max_retries + 1} attempts due to rate limiting")

        return response

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
                return [self.UNKNOWN_ASN]

        cached = self._cache_lookup_asn(asn_int)
        if cached is not None:
            log.debug(f"cache HIT for asn: {asn}")
            return cached

        log.debug(f"cache MISS for asn: {asn}")
        asn_data = await self._query_api_asn(asn_int)
        if asn_data:
            self._cache_store_asn(asn_data, asn_int)
            return asn_data
        return [self.UNKNOWN_ASN]

    async def ip_to_subnets(self, ip: str):
        """Return ASN info for *ip* using cached subnet ranges where possible."""

        ip_str = str(ipaddress.ip_address(ip))
        cached = self._cache_lookup_ip(ip_str)
        if cached is not None:
            log.debug(f"cache HIT for ip: {ip_str}")
            return cached or [self.UNKNOWN_ASN]

        log.debug(f"cache MISS for ip: {ip_str}")
        asn_data = await self._query_api_ip(ip_str)
        if asn_data:
            self._cache_store_ip(asn_data)
            return asn_data
        return [self.UNKNOWN_ASN]

    async def _query_api_ip(self, ip: str):
        # Build request URL using overridable base
        url = f"{self.asndb_ip_url}{ip}"
        response = await self._request_with_retry(url)
        if response is None:
            log.warning(f"ASN DB API: no response for {ip}")
            return None

        status = getattr(response, "status_code", 0)
        if status != 200:
            log.warning(f"ASN DB API: returned {status} for {ip}")
            return None

        try:
            raw = response.json()
        except Exception as e:
            log.warning(f"ASN DB API: JSON decode error for {ip}: {e}")
            return None

        if isinstance(raw, dict):
            subnets = raw.get("subnets")
            if isinstance(subnets, str):
                subnets = [subnets]
            if not subnets:
                subnets = [f"{ip}/32"]

            rec = {
                "asn": str(raw.get("asn", "")),
                "subnets": subnets,
                "name": raw.get("asn_name", ""),
                "description": raw.get("org", ""),
                "country": raw.get("country", ""),
            }
            return [rec]

        log.warning(f"ASN DB API: returned unexpected format for {ip}: {raw}")
        return None

    async def _query_api_asn(self, asn: str):
        url = f"{self.asndb_asn_url}{asn}"
        response = await self._request_with_retry(url)
        if response is None:
            log.warning(f"ASN DB API: no response for {asn}")
            return None

        status = getattr(response, "status_code", 0)
        if status != 200:
            log.warning(f"ASN DB API: returned {status} for {asn}")
            return None

        try:
            raw = response.json()
        except Exception as e:
            log.warning(f"ASN DB API: JSON decode error for {asn}: {e}")
            return None

        if isinstance(raw, dict):
            subnets = raw.get("subnets")
            if isinstance(subnets, str):
                subnets = [subnets]
            if not subnets:
                subnets = []

            rec = {
                "asn": str(raw.get("asn", "")),
                "subnets": subnets,
                "name": raw.get("asn_name", ""),
                "description": raw.get("org", ""),
                "country": raw.get("country", ""),
            }
            return [rec]

        log.warning(f"ASN DB API: returned unexpected format for {asn}: {raw}")
        return None

    def _cache_store_asn(self, asn_list, asn_id: int):
        """Cache ASN data by ASN ID"""
        self._asn_to_data_cache[asn_id] = asn_list
        log.debug(f"ASN cache ADD {asn_id} -> {asn_list[0].get('asn', '?') if asn_list else '?'}")

    def _cache_lookup_asn(self, asn_id: int):
        """Lookup cached ASN data by ASN ID"""
        return self._asn_to_data_cache.get(asn_id)

    def _cache_store_ip(self, asn_list):
        if not (self._tree4 or self._tree6):
            return
        for rec in asn_list:
            subnets = rec.get("subnets") or []
            if isinstance(subnets, str):
                subnets = [subnets]
            for p in subnets:
                try:
                    net = ipaddress.ip_network(p, strict=False)
                except ValueError:
                    continue
                tree = self._tree4 if net.version == 4 else self._tree6
                tree.insert(str(net), data=asn_list)
                self._subnet_to_asn_cache[str(net)] = asn_list
                log.debug(f"IP cache ADD {net} -> {asn_list[:1][0].get('asn', '?')}")

    def _cache_lookup_ip(self, ip: str):
        ip_obj = ipaddress.ip_address(ip)
        tree = self._tree4 if ip_obj.version == 4 else self._tree6
        node = tree.get_node(ip)
        if node and getattr(node, "data", None):
            return node.data
        return None
