from bbot.modules.report.base import BaseReportModule
from bbot.core.helpers.asn import ASNHelper


class asn(BaseReportModule):
    watched_events = ["IP_ADDRESS"]
    produced_events = ["ASN"]
    flags = ["safe", "passive", "subdomain-enum"]
    meta = {
        "description": "Query asndb for ASN information",
        "created_date": "2022-07-25",
        "author": "@TheTechromancer",
    }
    scope_distance_modifier = 1
    # we accept dupes to avoid missing data
    # because sometimes IP addresses are re-emitted with lower scope distances
    accept_dupes = True

    async def setup(self):
        self.unknown_asn = ASNHelper.UNKNOWN_ASN
        # Track ASN counts locally for reporting
        self.asn_counts = {}  # ASN number -> count mapping
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

        asn_data = await self.helpers.asn.ip_to_subnets(host_str)
        if asn_data:
            asn_number = asn_data.get("asn", 0)
            asn_description = asn_data.get("description", "")
            asn_name = asn_data.get("name", "")
            asn_country = asn_data.get("country", "")
            subnets = asn_data.get("subnets", [])

            # Track ASN subnet counts for reporting (only once per ASN)
            if asn_number and asn_number != 0:
                if asn_number not in self.asn_counts:
                    self.asn_counts[asn_number] = len(subnets)

            # Don't emit ASN 0 - it's reserved and indicates unknown ASN data
            if asn_number != 0:
                asn_event = self.make_event(asn_number, "ASN", parent=event)
                if asn_event:
                    await self.emit_event(
                        asn_event,
                        context=f"{{module}} looked up {event.data} and got {{event.type}}: AS{asn_number} ({asn_name}, {asn_description}, {asn_country})",
                    )

    async def report(self):
        """Generate an ASN summary table based on locally tracked ASN counts."""

        if not self.asn_counts:
            return

        # Build table rows sorted by ASN number (low to high)
        sorted_asns = sorted(self.asn_counts.items(), key=lambda x: int(x[0]))

        header = ["ASN", "Subnet Count", "Name", "Description", "Country"]
        table = []
        for asn_number, subnet_count in sorted_asns:
            # Get ASN details from helper
            asn_data = await self.helpers.asn.asn_to_subnets(asn_number)
            if asn_data:
                asn_name = asn_data.get("name", "")
                asn_description = asn_data.get("description", "")
                asn_country = asn_data.get("country", "")
            else:
                asn_name = asn_description = asn_country = "unknown"

            number = f"AS{asn_number}" if asn_number != 0 else str(asn_number)
            table.append(
                [
                    number,
                    f"{subnet_count:,}",
                    asn_name,
                    asn_description,
                    asn_country,
                ]
            )

        self.log_table(table, header, table_name="asns")
