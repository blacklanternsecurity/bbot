# bimi.py
#
# Checks for and parses common BIMI DNS TXT records, e.g. default._bimi.target.domain
#
# Example TXT record: "v=BIMI1; l=https://example.com/brand/logo.svg; a=https://example.com/brand/certificate.pem"
#
# BIMI records may contain a link to an SVG format brand authorised image, which may be useful for:
#  1. Sub-domain or otherwise unknown content hosting locations
#  2. Brand impersonation
#  3. May not be formatted/stripped of metadata correctly leading to some (low value probably) information exposure
#
# BIMI records may also contain a link to a PEM format X.509 VMC certificate, which may be similarly useful.
#
# We simply extract any URL's as URL_UNVERIFIED, no further parsing or download is done by this module in order to remain passive.
#
# The domain portion of any URL's is also passively checked and added as appropriate, for additional inspection by other modules.
#
# Files may be downloaded by other modules which respond to URL_UNVERIFIED events, if you have configured bbot to do so.
#
# NOTE: .svg file extensions are filtered from inclusion by default, modify "url_extension_blacklist" appropriately if you want the .svg image to be considered for download.
#
# NOTE: use the "filedownload" module if you to download .svg and .pem files. .pem will be downloaded by default, .svg will require a customised configuration for that module.
#
# The domain portion of any URL_UNVERIFIED's will be extracted by the various internal modules if .svg is not filtered.
#

from bbot.modules.base import BaseModule
from bbot.core.helpers.dns.helpers import service_record

import re

# Handle "v=BIMI1; l=; a=;" == RFC conformant explicit declination to publish, e.g. useful on a sub-domain if you don't want the sub-domain to have a BIMI logo, yet your registered domain does?
# Handle "v=BIMI1; l=; a=" == RFC non-conformant explicit declination to publish
# Handle "v=BIMI1; l=;" == RFC non-conformant explicit declination to publish
# Handle "v=BIMI1; l=" == RFC non-conformant explicit declination to publish
# Handle "v=BIMI1;" == RFC non-conformant explicit declination to publish
# Handle "v=BIMI1" == RFC non-conformant explicit declination to publish
# Handle "v=BIMI1;l=https://bimi.entrust.net/example.com/logo.svg;"
# Handle "v=BIMI1; l=https://bimi.entrust.net/example.com/logo.svg;"
# Handle "v=BIMI1;l=https://bimi.entrust.net/example.com/logo.svg;a=https://bimi.entrust.net/example.com/certchain.pem"
# Handle "v=BIMI1; l=https://bimi.entrust.net/example.com/logo.svg;a=https://bimi.entrust.net/example.com/certchain.pem;"
_bimi_regex = r"^v=(?P<v>BIMI1);* *(l=(?P<l>https*://[^;]*|)|);*( *a=((?P<a>https://[^;]*|)|);*)*$"
bimi_regex = re.compile(_bimi_regex, re.I)


class dnsbimi(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["URL_UNVERIFIED", "RAW_DNS_RECORD"]
    flags = ["subdomain-enum", "cloud-enum", "passive", "safe"]
    meta = {
        "description": "Check DNS_NAME's for BIMI records to find image and certificate hosting URL's",
        "author": "@colin-stubbs",
        "created_date": "2024-11-15",
    }
    options = {
        "emit_raw_dns_records": False,
        "emit_urls": True,
        "selectors": "default,email,mail,bimi",
    }
    options_desc = {
        "emit_raw_dns_records": "Emit RAW_DNS_RECORD events",
        "emit_urls": "Emit URL_UNVERIFIED events",
        "selectors": "CSV list of BIMI selectors to check",
    }

    async def setup(self):
        self.emit_raw_dns_records = self.config.get("emit_raw_dns_records", False)
        self.emit_urls = self.config.get("emit_urls", True)
        self._selectors = self.config.get("selectors", "").replace(", ", ",").split(",")

        return await super().setup()

    def _incoming_dedup_hash(self, event):
        # dedupe by parent
        parent_domain = self.helpers.parent_domain(event.data)
        return hash(parent_domain), "already processed parent domain"

    async def filter_event(self, event):
        if "_wildcard" in str(event.host).split("."):
            return False, "event is wildcard"

        # there's no value in inspecting service records
        if service_record(event.host) is True:
            return False, "service record detected"

        return True

    async def inspectBIMI(self, event, domain):
        parent_domain = self.helpers.parent_domain(event.data)
        rdtype = "TXT"

        for selector in self._selectors:
            tags = ["bimi-record", f"bimi-{selector}"]
            hostname = f"{selector}._bimi.{parent_domain}"

            r = await self.helpers.resolve_raw(hostname, type=rdtype)

            if r:
                raw_results, errors = r

                for answer in raw_results:
                    if self.emit_raw_dns_records:
                        await self.emit_event(
                            {
                                "host": hostname,
                                "type": rdtype,
                                "answer": answer.to_text(),
                            },
                            "RAW_DNS_RECORD",
                            parent=event,
                            tags=tags.append(f"{rdtype.lower()}-record"),
                            context=f"{rdtype} lookup on {hostname} produced {{event.type}}",
                        )

                    # we need to strip surrounding quotes and whitespace, as well as fix TXT data that may have been split across two different rdata's
                    # e.g. we will get a single string, but within that string we may have two parts such as:
                    # answer = '"part 1 that was really long" "part 2 that did not fit in part 1"'
                    s = answer.to_text().strip('"').strip().replace('" "', "")

                    bimi_match = bimi_regex.search(s)

                    if bimi_match and bimi_match.group("v") and "bimi" in bimi_match.group("v").lower():
                        if bimi_match.group("l") and bimi_match.group("l") != "":
                            if self.emit_urls:
                                await self.emit_event(
                                    bimi_match.group("l"),
                                    "URL_UNVERIFIED",
                                    parent=event,
                                    tags=tags.append("bimi-location"),
                                )

                        if bimi_match.group("a") and bimi_match.group("a") != "":
                            if self.emit_urls:
                                await self.emit_event(
                                    bimi_match.group("a"),
                                    "URL_UNVERIFIED",
                                    parent=event,
                                    tags=tags.append("bimi-authority"),
                                )

    async def handle_event(self, event):
        await self.inspectBIMI(event, event.host)


# EOF
