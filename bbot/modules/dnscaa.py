# dnscaa.py
#
# Checks for and parses CAA DNS TXT records for IODEF reporting destination email addresses and/or URL's.
#
# NOTE: when the target domain is initially resolved basic "dns_name_extraction_regex" matched targets will be extracted so we do not perform that again here.
#
# Example CAA records,
#   0 iodef "mailto:dnsadmin@example.com"
#   0 iodef "mailto:contact_pki@example.com"
#   0 iodef "mailto:ipladmin@example.com"
#   0 iodef "https://example.com/caa"
#   0 iodef "https://203.0.113.1/caa" <<< unlikely but possible?
#   0 iodef "https://[2001:db8::1]/caa" <<< unlikely but possible?
#
# We simply extract any URL's as URL_UNVERIFIED, no further activity against URL's is performed by this module in order to remain passive.
#
# Other modules which respond to URL_UNVERIFIED events may do so if you have configured bbot appropriately.
#
# The domain/IP portion of any URL_UNVERIFIED's should be extracted by the various internal modules.
#

from bbot.modules.base import BaseModule

from bbot.core.helpers.regexes import dns_name_extraction_regex, email_regex, url_regexes
from bbot.core.config.models import BaseModuleConfig, Field


class dnscaa(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME", "EMAIL_ADDRESS", "URL_UNVERIFIED"]
    flags = ["safe", "subdomain-enum", "email-enum", "passive"]
    meta = {"description": "Check for CAA records", "author": "@colin-stubbs", "created_date": "2024-05-26"}

    class Config(BaseModuleConfig):
        in_scope_only: bool = Field(True, description="Only check in-scope domains")
        dns_names: bool = Field(True, description="emit DNS_NAME events")
        emails: bool = Field(True, description="emit EMAIL_ADDRESS events")
        urls: bool = Field(True, description="emit URL_UNVERIFIED events")

    # accept DNS_NAMEs out to 2 hops if in_scope_only is False
    scope_distance_modifier = 2

    async def setup(self):
        self.in_scope_only = self.config.get("in_scope_only", True)
        self._dns_names = self.config.get("dns_names", True)
        self._emails = self.config.get("emails", True)
        self._urls = self.config.get("urls", True)
        return await super().setup()

    async def filter_event(self, event):
        if "_wildcard" in str(event.host).split("."):
            return False, "event is wildcard"

        # scope filtering
        if event.scope_distance > 0 and self.in_scope_only:
            return False, "event is not in scope"

        return True

    async def handle_event(self, event):
        tags = ["caa-record"]

        response = await self.helpers.dns.resolve_full(event.host, "CAA")

        for answer in response.response.answers:
            caa = answer.rdata.get("CAA")
            if not isinstance(caa, dict):
                continue

            raw_tag = caa.get("tag")
            # hickory wraps unrecognized CAA properties as {"Unknown": "name"}
            if isinstance(raw_tag, dict):
                raw_tag = raw_tag.get("Unknown", "")
            if not isinstance(raw_tag, str):
                continue
            tag = raw_tag.lower()

            value = caa.get("value") or {}
            # hickory wraps unrecognized values as {"Unknown": [byte_array]}
            if isinstance(value, dict) and isinstance(value.get("Unknown"), list):
                try:
                    value = {"raw_text": bytes(value["Unknown"]).decode()}
                except (ValueError, UnicodeDecodeError):
                    continue

            # iodef -> "Url" containing mailto: or https:// for incident reporting
            if tag == "iodef":
                target = value.get("Url") if isinstance(value, dict) else None
                if not target:
                    continue
                if self._emails:
                    for match in email_regex.finditer(target):
                        await self.emit_event(
                            target[match.start() : match.end()], "EMAIL_ADDRESS", tags=tags, parent=event
                        )
                if self._urls:
                    for url_regex in url_regexes:
                        for match in url_regex.finditer(target):
                            await self.emit_event(
                                target[match.start() : match.end()].strip('"').strip(),
                                "URL_UNVERIFIED",
                                tags=tags,
                                parent=event,
                            )

            # contactemail (RFC 8657) -> email for CA to contact domain owner
            elif tag == "contactemail":
                raw_text = value.get("raw_text") if isinstance(value, dict) else None
                if raw_text and self._emails:
                    for match in email_regex.finditer(raw_text):
                        await self.emit_event(
                            raw_text[match.start() : match.end()], "EMAIL_ADDRESS", tags=tags, parent=event
                        )

            # issue / issuewild -> "Issuer" containing the CA's domain
            elif tag.startswith("issue"):
                if not self._dns_names:
                    continue
                issuer = value.get("Issuer") if isinstance(value, dict) else None
                # blastdns models this as ["domain", [extensions]]; an empty issuer
                # ("explicit denial") resolves to None or [None, []]
                if isinstance(issuer, (list, tuple)) and issuer and issuer[0]:
                    name_text = str(issuer[0])
                    for match in dns_name_extraction_regex.finditer(name_text):
                        await self.emit_event(
                            name_text[match.start() : match.end()], "DNS_NAME", tags=tags, parent=event
                        )


# EOF
