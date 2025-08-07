from bbot.modules.report.base import BaseReportModule


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
        self.unknown_asn = {
            "asn": "UNKNOWN",
            "subnet": "0.0.0.0/32",
            "name": "unknown",
            "description": "unknown",
            "country": "",
        }
        return True

    async def filter_event(self, event):
        if str(event.module) == "ipneighbor":
            return False
        if getattr(event.host, "is_private", False):
            return False
        return True

    async def handle_event(self, event):
        host = event.host
        asns = await self.helpers.asn.get(str(host))

        for asn in asns:
            # Calculate subnet count
            subnets = asn.get("subnets", [])
            subnet_count = len(subnets)

            # Add new summary field
            asn["subnet_count"] = subnet_count

            emails = asn.pop("emails", [])
            asn_event = self.make_event(asn, "ASN", parent=event)
            if not asn_event:
                continue

            asn_number = asn.get("asn", "")
            asn_desc = asn.get("description", "")
            asn_name = asn.get("name", "")
            asn_country = asn.get("country", "")

            await self.emit_event(
                asn_event,
                context=f"{{module}} looked up {event.data} and got {{event.type}}: AS{asn_number} ({asn_name}, {asn_desc}, {asn_country})",
            )

            for email in emails:
                await self.emit_event(
                    email,
                    "EMAIL_ADDRESS",
                    parent=asn_event,
                    context=f"{{module}} retrieved details for AS{asn_number} and found {{event.type}}: {{event.data}}",
                )

    async def report(self):
        """Generate an ASN summary table based on the helper's cached subnets."""

        subnet_cache = getattr(self.helpers.asn, "_subnet_map", {})
        if not subnet_cache:
            return

        # Aggregate data per ASN
        asn_agg = {}
        for subnet, recs in subnet_cache.items():
            for rec in recs:
                asn = str(rec.get("asn", "UNKNOWN"))
                entry = asn_agg.setdefault(
                    asn,
                    {
                        "name": rec.get("name", ""),
                        "description": rec.get("description", ""),
                        "country": rec.get("country", ""),
                        "subnets": set(),
                    },
                )
                entry["subnets"].add(subnet)

        # Build table rows sorted by subnet count desc
        sorted_asns = sorted(asn_agg.items(), key=lambda x: len(x[1]["subnets"]), reverse=True)

        header = ["ASN", "Subnet Count", "Name", "Description", "Country"]
        table = []
        for asn, data in sorted_asns:
            number = "AS" + asn if asn != "UNKNOWN" else asn
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
