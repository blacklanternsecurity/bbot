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

from bbot.modules.base import BaseModule

import logging

from bbot.core.helpers.regexes import email_regex, url_regexes

log = logging.getLogger("bbot.core.helpers.dns")


class dnscaa(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["EMAIL_ADDRESS", "URL_UNVERIFIED"]
    flags = ["subdomain-enum", "email-enum", "passive", "safe"]
    meta = {"description": "Check for CAA iodef records"}
    options = {
        "max_event_handlers": 10,
    }
    options_desc = {
        "max_event_handlers": "How many instances of the module to run concurrently",
    }
    _max_event_handlers = 10

    async def setup(self):
        self._max_event_handlers = self.config.get("max_event_handlers", 10)
        return await super().setup()

    def _incoming_dedup_hash(self, event):
        # dedupe by parent
        parent_domain = self.helpers.parent_domain(event.data)
        return hash(parent_domain), "already processed parent domain"

    async def filter_event(self, event):
        return True

    async def handle_event(self, event):
        parent_domain = self.helpers.parent_domain(event.data)
        query = f"{parent_domain}"
        try:
            r = await self.helpers.resolve_raw(query, type="caa")

            if r:
                raw_results, errors = r

                for rdtype, answers in raw_results:
                    for answer in answers:
                        s = self.helpers.smart_decode(f"{answer}")

                        if "iodef" in s:
                            for match in email_regex.finditer(s):
                                start, end = match.span()
                                email = s[start:end]

                                await self.emit_event(email, "EMAIL_ADDRESS", tags=["caa-record"], source=event)

                            for url_regex in url_regexes:
                                for match in url_regex.finditer(s):
                                    start, end = match.span()
                                    url = s[start:end].strip('"').strip()

                                    await self.emit_event(url, "URL_UNVERIFIED", source=event, tags="caa-record")

        except BaseException:
            log.trace(f"Caught exception in dnscaa module:")
            raise


# EOF
