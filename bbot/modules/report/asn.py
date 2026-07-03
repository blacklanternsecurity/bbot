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
        self.asn_metadata = {}
        return True

    async def filter_event(self, event):
        if str(event.module) == "ipneighbor":
            return False
        # only look up globally-routable IPs; private/CGNAT/reserved space has no public ASN
        if not getattr(event.host, "is_global", True):
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

            if asn_number and asn_number != 0:
                if asn_number not in self.asn_metadata:
                    self.asn_metadata[asn_number] = {
                        "subnet_count": len(subnets),
                        "name": asn_name,
                        "description": asn_description,
                        "country": asn_country,
                    }

            # Don't emit ASN 0 - it's reserved and indicates unknown ASN data
            if asn_number != 0:
                asn_event = self.make_event(asn_number, "ASN", parent=event)
                if asn_event:
                    await self.emit_event(
                        asn_event,
                        context=f"{{module}} looked up {event.pretty_string} and got {{event.type}}: AS{asn_number} ({asn_name}, {asn_description}, {asn_country})",
                    )

    async def report(self):
        if not self.asn_metadata:
            return

        sorted_asns = sorted(self.asn_metadata.items(), key=lambda x: int(x[0]))

        header = ["ASN", "Subnet Count", "Name", "Description", "Country"]
        table = []
        for asn_number, metadata in sorted_asns:
            table.append(
                [
                    f"AS{asn_number}",
                    f"{metadata['subnet_count']:,}",
                    metadata["name"],
                    metadata["description"],
                    metadata["country"],
                ]
            )

        self.log_table(table, header, table_name="asns")
