import ipaddress
import logging
from radixtarget.tree.ip import IPRadixTree

log = logging.getLogger("bbot.core.helpers.asn")


class ASNHelper:
    asndb_url = "http://157.230.95.177:9000/v1/ip/"

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        # IP radix trees (authoritative store) – IPv4 and IPv6
        self._tree4: IPRadixTree = IPRadixTree()
        self._tree6: IPRadixTree = IPRadixTree()
        self._prefix_map: dict[str, list] = {}

    # Default record used when no ASN data can be found
    UNKNOWN_ASN = {
        "asn": "UNKNOWN",
        "subnet": "0.0.0.0/32",
        "name": "unknown",
        "description": "unknown",
        "country": "",
    }

    async def get(self, ip: str):
        """Return ASN info for *ip* using cached subnet ranges where possible."""

        ip_str = str(ipaddress.ip_address(ip))
        cached = self._cache_lookup(ip_str)
        if cached is not None:
            log.debug(f"cache HIT for ip: {ip_str}")
            return cached or [self.UNKNOWN_ASN]

        log.debug(f"cache MISS for ip: {ip_str}")
        asn_data = await self._query_api(ip_str)
        if asn_data:
            self._cache_subnets(asn_data)
            return asn_data
        return [self.UNKNOWN_ASN]

    async def _query_api(self, ip: str):
        # Build request URL using overridable base
        url = f"{self.asndb_url}{ip}"
        try:
            response = await self.parent_helper.request(url, timeout=15)
            if response is None:
                log.warning(f"ASN API no response for {ip}")
                return None

            status = getattr(response, "status_code", 0)
            if status != 200:
                log.warning(f"ASN API returned {status} for {ip}")
                return None

            try:
                raw = response.json()
            except Exception as e:
                log.warning(f"ASN API JSON decode error for {ip}: {e}")
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

            log.warning(f"ASN API returned unexpected format for {ip}: {raw}")
            return None
        except Exception as e:
            log.warning(f"ASN API request error to url {url} for {ip}: {e}")
            return None

    def _cache_subnets(self, asn_list):
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
                self._prefix_map[str(net)] = asn_list
                log.debug(f"ASN cache ADD {net} -> {asn_list[:1][0].get('asn', '?')}")

    def _cache_lookup(self, ip: str):
        ip_obj = ipaddress.ip_address(ip)
        tree = self._tree4 if ip_obj.version == 4 else self._tree6
        node = tree.get_node(ip)
        if node and getattr(node, "data", None):
            return node.data
        return None
