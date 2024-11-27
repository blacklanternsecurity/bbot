# dnstlsrpt.py
#
# Checks for and parses common TLS-RPT TXT records, e.g. _smtp._tls.target.domain
#
# TLS-RPT policies may contain email addresses or URL's for reporting destinations, typically the email addresses are software processed inboxes, but they may also be to individual humans or team inboxes.
#
# The domain portion of any email address or URL is also passively checked and added as appropriate, for additional inspection by other modules.
#
# Example records,
# _smtp._tls.example.com TXT "v=TLSRPTv1;rua=https://tlsrpt.azurewebsites.net/report"
# _smtp._tls.example.net TXT "v=TLSRPTv1; rua=mailto:sts-reports@example.net;"
#
# TODO: extract %{UNIQUE_ID}% from hosted services as ORG_STUB ?
#   e.g. %{UNIQUE_ID}%@tlsrpt.hosted.service.provider is usually a tenant specific ID.
#   e.g. tlsrpt@%{UNIQUE_ID}%.hosted.service.provider is usually a tenant specific ID.

from bbot.modules.base import BaseModule
from bbot.core.helpers.dns.helpers import service_record

import re

from bbot.core.helpers.regexes import email_regex, url_regexes

_tlsrpt_regex = r"^v=(?P<v>TLSRPTv[0-9]+); *(?P<kvps>.*)$"
tlsrpt_regex = re.compile(_tlsrpt_regex, re.I)

_tlsrpt_kvp_regex = r"(?P<k>\w+)=(?P<v>[^;]+);*"
tlsrpt_kvp_regex = re.compile(_tlsrpt_kvp_regex)

_csul = r"(?P<uri>[^, ]+)"
csul = re.compile(_csul)


class dnstlsrpt(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["EMAIL_ADDRESS", "URL_UNVERIFIED", "RAW_DNS_RECORD"]
    flags = ["subdomain-enum", "cloud-enum", "email-enum", "passive", "safe"]
    meta = {
        "description": "Check for TLS-RPT records",
        "author": "@colin-stubbs",
        "created_date": "2024-07-26",
    }
    options = {
        "emit_emails": True,
        "emit_raw_dns_records": False,
        "emit_urls": True,
        "emit_vulnerabilities": True,
    }
    options_desc = {
        "emit_emails": "Emit EMAIL_ADDRESS events",
        "emit_raw_dns_records": "Emit RAW_DNS_RECORD events",
        "emit_urls": "Emit URL_UNVERIFIED events",
        "emit_vulnerabilities": "Emit VULNERABILITY events",
    }

    async def setup(self):
        self.emit_emails = self.config.get("emit_emails", True)
        self.emit_raw_dns_records = self.config.get("emit_raw_dns_records", False)
        self.emit_urls = self.config.get("emit_urls", True)
        self.emit_vulnerabilities = self.config.get("emit_vulnerabilities", True)
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

    async def handle_event(self, event):
        rdtype = "TXT"
        tags = ["tlsrpt-record"]
        hostname = f"_smtp._tls.{event.host}"

        r = await self.helpers.resolve_raw(hostname, type=rdtype)

        if r:
            raw_results, errors = r
            for answer in raw_results:
                if self.emit_raw_dns_records:
                    await self.emit_event(
                        {"host": hostname, "type": rdtype, "answer": answer.to_text()},
                        "RAW_DNS_RECORD",
                        parent=event,
                        tags=tags.append(f"{rdtype.lower()}-record"),
                        context=f"{rdtype} lookup on {hostname} produced {{event.type}}",
                    )

                # we need to fix TXT data that may have been split across two different rdata's
                # e.g. we will get a single string, but within that string we may have two parts such as:
                # answer = '"part 1 that was really long" "part 2 that did not fit in part 1"'
                # NOTE: the leading and trailing double quotes are essential as part of a raw DNS TXT record, or another record type that contains a free form text string as a component.
                s = answer.to_text().strip('"').replace('" "', "")

                # validate TLSRPT record, tag appropriately
                tlsrpt_match = tlsrpt_regex.search(s)

                if (
                    tlsrpt_match
                    and tlsrpt_match.group("v")
                    and tlsrpt_match.group("kvps")
                    and tlsrpt_match.group("kvps") != ""
                ):
                    for kvp_match in tlsrpt_kvp_regex.finditer(tlsrpt_match.group("kvps")):
                        key = kvp_match.group("k").lower()

                        if key == "rua":
                            for csul_match in csul.finditer(kvp_match.group("v")):
                                if csul_match.group("uri"):
                                    for match in email_regex.finditer(csul_match.group("uri")):
                                        start, end = match.span()
                                        email = csul_match.group("uri")[start:end]

                                        if self.emit_emails:
                                            await self.emit_event(
                                                email,
                                                "EMAIL_ADDRESS",
                                                tags=tags.append(f"tlsrpt-record-{key}"),
                                                parent=event,
                                            )

                                    for url_regex in url_regexes:
                                        for match in url_regex.finditer(csul_match.group("uri")):
                                            start, end = match.span()
                                            url = csul_match.group("uri")[start:end]

                                            if self.emit_urls:
                                                await self.emit_event(
                                                    url,
                                                    "URL_UNVERIFIED",
                                                    tags=tags.append(f"tlsrpt-record-{key}"),
                                                    parent=event,
                                                )


# EOF
