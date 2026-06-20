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

    FAILURE_THRESHOLD = 5

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        self._client = None
        self._consecutive_failures = 0
        self._circuit_broken = False

    @property
    def client(self):
        if self._client is None:
            from asndb import ASNDB

            ssl_verify = self.parent_helper.web_config.get("ssl_verify_infrastructure", True)
            api_key = self.parent_helper.config.get("bbot_io_api_key", None)
            self._client = ASNDB(bbot_io_api_key=api_key, verify=ssl_verify)
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

    def _record_failure(self):
        self._consecutive_failures += 1
        if self._consecutive_failures >= self.FAILURE_THRESHOLD and not self._circuit_broken:
            self._circuit_broken = True
            log.critical(
                "ASN lookups disabled for the rest of this scan after %d consecutive failures. "
                "The bbot.io ASN API could not be reached (this may be due to regional network restrictions). "
                "ASN enrichment data will not be available.",
                self.FAILURE_THRESHOLD,
            )

    async def ip_to_subnets(self, ip):
        """Return ASN info for an IP address."""
        if self._circuit_broken:
            return self.UNKNOWN_ASN
        try:
            response = await self.client.lookup_ip(str(ip), include_subnets=True)
        except Exception as e:
            log.warning(f"ASN lookup failed for IP {ip}: {e}")
            self._record_failure()
            return self.UNKNOWN_ASN
        self._consecutive_failures = 0
        return self._normalize(response)

    async def asn_to_subnets(self, asn):
        """Return ASN info (including subnets) for an ASN number."""
        if self._circuit_broken:
            return self.UNKNOWN_ASN
        if isinstance(asn, str):
            try:
                asn = int(asn.lower().lstrip("as"))
            except ValueError:
                log.warning(f"Invalid ASN format: {asn}")
                return self.UNKNOWN_ASN
        try:
            response = await self.client.lookup_asn(asn, include_subnets=True)
        except Exception as e:
            log.warning(f"ASN lookup failed for AS{asn}: {e}")
            self._record_failure()
            return self.UNKNOWN_ASN
        self._consecutive_failures = 0
        return self._normalize(response)

    async def cleanup(self):
        """Clean up the asndb client."""
        if self._client is not None:
            try:
                await self._client.cleanup()
            except Exception:
                pass
            self._client = None
            # Reset the asndb global singleton so the next ASNDB() call
            # creates a fresh client instead of returning the closed one
            import asndb.asndb

            asndb.asndb.asndb_client = None
