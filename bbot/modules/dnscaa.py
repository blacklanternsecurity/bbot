# dnscaa.py
#
# Checks for and parses CAA DNS TXT records for IODEF reporting destination email addresses and/or URL's.
#
# NOTE: when the target domain is initially resolved basic "dns_name_regex" matched targets will be extracted so we do not perform that again here.
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

import re

from bbot.core.helpers.regexes import dns_name_regex, email_regex, url_regexes

# Handle '0 iodef "mailto:support@hcaptcha.com"'
# Handle '1 iodef "https://some.host.tld/caa;"'
# Handle '0 issue "pki.goog; cansignhttpexchanges=yes; somethingelse=1"'
# Handle '1 issue ";"' == explicit denial for any wildcard issuance.
# Handle '128 issuewild "comodoca.com"'
# Handle '128 issuewild ";"' == explicit denial for any wildcard issuance.
_caa_regex = r"^(?P<flags>[0-9]+) +(?P<property>\w+) +\"(?P<text>[^;\"]*);* *(?P<extensions>[^\"]*)\"$"
caa_regex = re.compile(_caa_regex)

_caa_extensions_kvp_regex = r"(?P<k>\w+)=(?P<v>[^;]+)"
caa_extensions_kvp_regex = re.compile(_caa_extensions_kvp_regex)


class dnscaa(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME", "EMAIL_ADDRESS", "URL_UNVERIFIED"]
    flags = ["subdomain-enum", "email-enum", "passive", "safe"]
    meta = {"description": "Check for CAA records", "author": "@colin-stubbs", "created_date": "2024-05-26"}
    options = {
        "in_scope_only": True,
        "dns_names": True,
        "emails": True,
        "urls": True,
    }
    options_desc = {
        "in_scope_only": "Only check in-scope domains",
        "dns_names": "emit DNS_NAME events",
        "emails": "emit EMAIL_ADDRESS events",
        "urls": "emit URL_UNVERIFIED events",
    }
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

        r = await self.helpers.resolve_raw(event.host, type="caa")

        if r:
            raw_results, errors = r

            for answer in raw_results:
                s = answer.to_text().strip().replace('" "', "")

                # validate CAA record vi regex so that we can determine what to do with it.
                caa_match = caa_regex.search(s)

                if caa_match and caa_match.group("flags") and caa_match.group("property") and caa_match.group("text"):
                    # it's legit.
                    if caa_match.group("property").lower() == "iodef":
                        if self._emails:
                            for match in email_regex.finditer(caa_match.group("text")):
                                start, end = match.span()
                                email = caa_match.group("text")[start:end]

                                await self.emit_event(email, "EMAIL_ADDRESS", tags=tags, parent=event)

                        if self._urls:
                            for url_regex in url_regexes:
                                for match in url_regex.finditer(caa_match.group("text")):
                                    start, end = match.span()
                                    url = caa_match.group("text")[start:end].strip('"').strip()

                                    await self.emit_event(url, "URL_UNVERIFIED", tags=tags, parent=event)

                    elif caa_match.group("property").lower().startswith("issue"):
                        if self._dns_names:
                            for match in dns_name_regex.finditer(caa_match.group("text")):
                                start, end = match.span()
                                name = caa_match.group("text")[start:end]

                                await self.emit_event(name, "DNS_NAME", tags=tags, parent=event)


# EOF
