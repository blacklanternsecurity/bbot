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

    def _normalize(self, raw):
        """Convert asndb response dict to BBOT internal format."""
        if raw is None or raw.get("asn", 0) == 0:
            return self.UNKNOWN_ASN
        return {
            "asn": int(raw.get("asn", 0)),
            "subnets": raw.get("subnets", []),
            "name": raw.get("asn_name") or raw.get("name") or "",
            "description": raw.get("org") or raw.get("description") or "",
            "country": raw.get("country") or "",
        }

    async def ip_to_subnets(self, ip):
        """Return ASN info for an IP address."""
        try:
            raw = await self.client.lookup_ip(str(ip))
        except Exception as e:
            log.warning(f"ASN lookup failed for IP {ip}: {e}")
            return self.UNKNOWN_ASN
        return self._normalize(raw)

    async def asn_to_subnets(self, asn):
        """Return ASN info (including subnets) for an ASN number."""
        if isinstance(asn, str):
            try:
                asn = int(asn.lower().lstrip("as"))
            except ValueError:
                log.warning(f"Invalid ASN format: {asn}")
                return self.UNKNOWN_ASN
        try:
            raw = await self.client.lookup_asn(int(asn))
        except Exception as e:
            log.warning(f"ASN lookup failed for AS{asn}: {e}")
            return self.UNKNOWN_ASN
        return self._normalize(raw)

    async def cleanup(self):
        """Clean up the asndb client."""
        if self._client is not None:
            try:
                await self._client.cleanup()
            except Exception:
                pass
