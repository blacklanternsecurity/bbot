import ipaddress
from bbot.modules.report.base import BaseReportModule
from bbot.core.helpers.asn import ASNHelper


class asn(BaseReportModule):
    watched_events = ["IP_ADDRESS"]
    produced_events = ["ASN"]
    flags = ["passive", "subdomain-enum", "safe"]
    meta = {
        "description": "Query ripe and bgpview.io for ASNs",
        "created_date": "2022-07-25",
        "author": "@TheTechromancer",
    }
    scope_distance_modifier = 1
    # we accept dupes to avoid missing data
    # because sometimes IP addresses are re-emitted with lower scope distances
    accept_dupes = True

    async def setup(self):
        self.unknown_asn = ASNHelper.UNKNOWN_ASN
        # Track ASN data locally instead of relying on cache
        self.asn_data = {}  # ASN number -> ASN record mapping
        self.processed_subnets = {}  # subnet -> ASN number mapping for quick lookups
        return True

    async def filter_event(self, event):
        if str(event.module) == "ipneighbor":
            return False
        if getattr(event.host, "is_private", False):
            return False
        return True

    async def handle_event(self, event):
        host = event.host
        host_str = str(host)

        # Check if this IP is already covered by a subnet we've processed
        try:
            ip_obj = ipaddress.ip_address(host_str)
            for subnet_str, asn_number in self.processed_subnets.items():
                try:
                    subnet = ipaddress.ip_network(subnet_str, strict=False)
                    if ip_obj in subnet:
                        self.debug(
                            f"IP {host_str} already covered by processed subnet {subnet_str} (ASN {asn_number})"
                        )
                        return
                except ValueError:
                    continue
        except ValueError:
            pass  # Invalid IP address, continue with normal processing

        asn_data = await self.helpers.asn.ip_to_subnets(host_str)
        if asn_data:
            asn_record = asn_data
            asn_number = asn_record.get("asn")
            asn_description = asn_record.get("description", "")
            asn_name = asn_record.get("name", "")
            asn_country = asn_record.get("country", "")
            subnets = asn_record.get("subnets", [])

            # Store ASN data locally for reporting
            if asn_number and asn_number != "UNKNOWN" and asn_number not in self.asn_data:
                self.asn_data[asn_number] = {
                    "name": asn_name,
                    "description": asn_description,
                    "country": asn_country,
                    "subnets": set(subnets),
                }
                # Track processed subnets for quick lookups
                for subnet in subnets:
                    self.processed_subnets[subnet] = asn_number

            emails = asn_record.get("emails", [])
            # Don't emit ASN 0 - it's reserved and indicates unknown ASN data
            if asn_number != "0":
                asn_event = self.make_event(int(asn_number), "ASN", parent=event)
                if asn_event:
                    await self.emit_event(
                        asn_event,
                        context=f"{{module}} looked up {event.data} and got {{event.type}}: AS{asn_number} ({asn_name}, {asn_description}, {asn_country})",
                    )

                    for email in emails:
                        await self.emit_event(
                            email,
                            "EMAIL_ADDRESS",
                            parent=asn_event,
                            context=f"{{module}} retrieved details for AS{asn_number} and found {{event.type}}: {{event.data}}",
                        )

    async def report(self):
        """Generate an ASN summary table based on locally tracked ASN data."""

        if not self.asn_data:
            return

        # Build table rows sorted by subnet count desc
        sorted_asns = sorted(self.asn_data.items(), key=lambda x: len(x[1]["subnets"]), reverse=True)

        header = ["ASN", "Subnet Count", "Name", "Description", "Country"]
        table = []
        for asn, data in sorted_asns:
            number = "AS" + asn if asn != "0" else asn
            table.append(
                [
                    number,
                    f"{len(data['subnets']):,}",
                    data["name"],
                    data["description"],
                    data["country"],
                ]
            )

        self.log_table(table, header, table_name="asns")
