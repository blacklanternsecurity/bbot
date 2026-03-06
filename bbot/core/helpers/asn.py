import logging

log = logging.getLogger("bbot.core.helpers.asn")


class ASNHelper:
    """Thin wrapper around the asndb library for ASN lookups.

    Delegates all HTTP, caching, and retry logic to the asndb library.
    Normalizes response dicts to the BBOT-internal format with keys:
        asn, subnets, name, description, country
    """

    UNKNOWN_ASN = {
        "asn": 0,
        "subnets": [],
        "name": "Unknown",
        "description": "Unknown ASN",
        "country": "Unknown",
    }

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        self._client = None

    @property
    def client(self):
        if self._client is None:
            from asndb import ASNDB

            self._client = ASNDB()
        return self._client

    def _normalize(self, response):
        """Convert asndb response dict to BBOT internal format."""
        if response is None or response.get("asn", 0) == 0:
            return self.UNKNOWN_ASN
        return {
            "asn": int(response.get("asn", 0)),
            "subnets": response.get("subnets", []),
            "name": response.get("asn_name") or response.get("name") or "",
            "description": response.get("org") or response.get("description") or "",
            "country": response.get("country") or "",
        }

    async def ip_to_subnets(self, ip):
        """Return ASN info for an IP address."""
        try:
            response = await self.client.lookup_ip(str(ip), include_subnets=True)
        except Exception as e:
            log.warning(f"ASN lookup failed for IP {ip}: {e}")
            return self.UNKNOWN_ASN
        return self._normalize(response)

    async def asn_to_subnets(self, asn):
        """Return ASN info (including subnets) for an ASN number."""
        if isinstance(asn, str):
            try:
                asn = int(asn.lower().lstrip("as"))
            except ValueError:
                log.warning(f"Invalid ASN format: {asn}")
                return self.UNKNOWN_ASN
        try:
            response = await self.client.lookup_asn(str(asn), include_subnets=True)
        except Exception as e:
            log.warning(f"ASN lookup failed for AS{asn}: {e}")
            return self.UNKNOWN_ASN
        return self._normalize(response)

    async def cleanup(self):
        """Clean up the asndb client."""
        if self._client is not None:
            try:
                await self._client.cleanup()
            except Exception:
                pass
