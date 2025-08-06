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
            #        "country": "",
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
            # Calculate prefix count
            prefixes = asn.get("prefixes", [])
            prefix_count = len(prefixes)

            # Add new summary field
            asn["prefix_count"] = prefix_count

            emails = asn.pop("emails", [])
            asn_event = self.make_event(asn, "ASN", parent=event)
            if not asn_event:
                continue

            asn_number = asn.get("asn", "")
            asn_desc = asn.get("description", "")
            asn_name = asn.get("name", "")
            #    asn_subnet = asn.get("subnet", "")

            await self.emit_event(
                asn_event,
                context=f"{{module}} looked up {event.data} and got {{event.type}}: AS{asn_number} ({asn_name}, {asn_desc}",  # , {asn_subnet})",
            )

            for email in emails:
                await self.emit_event(
                    email,
                    "EMAIL_ADDRESS",
                    parent=asn_event,
                    context=f"{{module}} retrieved details for AS{asn_number} and found {{event.type}}: {{event.data}}",
                )

    async def report(self):
        """Generate an ASN summary table based on the helper's cached prefixes."""

        prefix_cache = getattr(self.helpers.asn, "_prefix_map", {})
        if not prefix_cache:
            return

        # Aggregate data per ASN
        asn_agg = {}
        for prefix, recs in prefix_cache.items():
            for rec in recs:
                asn = str(rec.get("asn", "UNKNOWN"))
                entry = asn_agg.setdefault(
                    asn,
                    {
                        "name": rec.get("name", ""),
                        "description": rec.get("description", ""),
                        "country": rec.get("country", ""),
                        "prefixes": set(),
                    },
                )
                entry["prefixes"].add(prefix)

        # Build table rows sorted by prefix count desc
        sorted_asns = sorted(asn_agg.items(), key=lambda x: len(x[1]["prefixes"]), reverse=True)

        header = ["ASN", "Prefix Count", "Name", "Description"]
        table = []
        for asn, data in sorted_asns:
            number = "AS" + asn if asn != "UNKNOWN" else asn
            table.append([
                number,
                f"{len(data['prefixes']):,}",
                data["name"],
                data["description"],
            ])

        self.log_table(table, header, table_name="asns")
