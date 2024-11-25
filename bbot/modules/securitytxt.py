# securitytxt.py
#
# Checks for/parses https://target.domain/.well-known/security.txt
#
# Refer to: https://securitytxt.org/
#
# security.txt may contain email addresses and URL's, and possibly IP addresses.
#
# Example security.txt:
#
#   Contact: mailto:security.reports@example.com
#   Expires: 2028-05-31T14:00:00.000Z
#   Encryption: https://example.com/security.pgp
#   Preferred-Languages: en, es
#   Canonical: https://example.com/.well-known/security.txt
#   Canonical: https://www.example.com/.well-known/security.txt
#   Policy: https://example.com/security-policy.html
#   Hiring: https://example.com/jobs.html
#
# Example security.txt with PGP signature:
#
#   -----BEGIN PGP SIGNED MESSAGE-----
#   Hash: SHA512
#
#   Contact: https://vdp.example.com
#   Expires: 2025-01-01T00:00:00.000Z
#   Preferred-Languages: fr, en
#   Canonical: https://example.com/.well-known/security.txt
#   Policy: https://example.com/cert
#   Hiring: https://www.careers.example.com
#   -----BEGIN PGP SIGNATURE-----
#
#   iQIzBAEBCgAdFiEELC1a63jHPhyV60KPsvWy9dDkrigFAmJBypcACgkQsvWy9dDk
#   rijXHQ//Qya3hUSy5PYW+fI3eFP1+ak6gYq3Cbzkf57cqiBhxGetIGIGNJ6mxgjS
#   KAuvXLMUWgZD73r//fjZ5v1lpuWmpt54+ecat4DgcVCvFKYpaH+KBlay8SX7XtQH
#   9T2NXMcez353TMR3EUOdLwdBzGZprf0Ekg9EzaHKMk0k+A4D9CnSb8Y6BKDPC7wr
#   eadwDIR9ESo0va4sjjcllCG9MF5hqK25SfsKriCSEAMhse2FToEBbw8ImkPKowMN
#   whJ4MIVlBxybu6XoIyk3n7HRRduijywy7uV80pAkhk/hL6wiW3M956FiahfRI6ad
#   +Gky/Ri5TjwAE/x5DhUH8O2toPsn71DeIE4geKfz5d/v41K0yncdrHjzbj0CAHu3
#   wVWLKnEp8RVqTlOR8jU0HqQUQy8iZk4LY91ROv+QjG/jUTWlwun8Ljh+YUeJTMRp
#   MGftCdCrrYjIy5aEQqWztt+dXKac/9e1plq3yyfuW1L+wG3zS7X+NpIJgygMvEwT
#   L3dqfQf63sjk8kWIZMVnicHBlc6BiLqUn020l+pkIOr4MuuJmIlByhlnfqH7YM8k
#   VShwDx7rs4Hj08C7NVCYIySaM2jM4eNKGt9V5k1F1sklCVfYaT8OqOhJrzhcisOC
#   YcQDhjt/iZTR8SzrHO7kFZbaskIp2P7JMaPax2fov15AnNHQQq8=
#   =8vfR
#   -----END PGP SIGNATURE-----

from bbot.modules.base import BaseModule

import re

from bbot.core.helpers.regexes import email_regex, url_regexes

_securitytxt_regex = r"^(?P<k>\w+): *(?P<v>.*)$"
securitytxt_regex = re.compile(_securitytxt_regex, re.I | re.M)


class securitytxt(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["EMAIL_ADDRESS", "URL_UNVERIFIED"]
    flags = ["subdomain-enum", "cloud-enum", "active", "web-basic", "safe"]
    meta = {
        "description": "Check for security.txt content",
        "author": "@colin-stubbs",
        "created_date": "2024-05-26",
    }
    options = {
        "emails": True,
        "urls": True,
    }
    options_desc = {
        "emails": "emit EMAIL_ADDRESS events",
        "urls": "emit URL_UNVERIFIED events",
    }

    async def setup(self):
        self._emails = self.config.get("emails", True)
        self._urls = self.config.get("urls", True)
        return await super().setup()

    def _incoming_dedup_hash(self, event):
        # dedupe by parent
        parent_domain = self.helpers.parent_domain(event.data)
        return hash(parent_domain), "already processed parent domain"

    async def filter_event(self, event):
        if "_wildcard" in str(event.host).split("."):
            return False, "event is wildcard"
        return True

    async def handle_event(self, event):
        tags = ["securitytxt-policy"]
        url = f"https://{event.host}/.well-known/security.txt"

        r = await self.helpers.request(url, method="GET")

        if r is None or r.status_code != 200:
            # it doesn't look like we got a valid response...
            return

        try:
            s = r.text
        except Exception:
            s = ""

        # avoid parsing the response unless it looks, at a very basic level, like an actual security.txt
        s_lower = s.lower()
        if "contact: " in s_lower or "expires: " in s_lower:
            for securitytxt_match in securitytxt_regex.finditer(s):
                v = securitytxt_match.group("v")

                for match in email_regex.finditer(v):
                    start, end = match.span()
                    email = v[start:end]

                    if self._emails:
                        await self.emit_event(email, "EMAIL_ADDRESS", parent=event, tags=tags)

                for url_regex in url_regexes:
                    for match in url_regex.finditer(v):
                        start, end = match.span()
                        found_url = v[start:end]

                        if found_url != url and self._urls is True:
                            await self.emit_event(found_url, "URL_UNVERIFIED", parent=event, tags=tags)


# EOF
