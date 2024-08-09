from bbot.modules.report.base import BaseReportModule


class affiliates(BaseReportModule):
    watched_events = ["*"]
    produced_events = []
    flags = ["passive", "safe", "affiliates"]
    meta = {
        "description": "Summarize affiliate domains at the end of a scan",
        "created_date": "2022-07-25",
        "author": "@TheTechromancer",
    }
    scope_distance_modifier = None
    accept_dupes = True

    async def setup(self):
        self.affiliates = {}
        return True

    async def handle_event(self, event):
        self.add_affiliate(event)

    async def report(self):
        affiliates = sorted(self.affiliates.items(), key=lambda x: x[-1]["weight"], reverse=True)
        header = ["Affiliate", "Score", "Count"]
        table = []
        for domain, stats in affiliates:
            count = stats["count"]
            weight = stats["weight"]
            table.append([domain, f"{weight:.2f}", f"{count:,}"])
        self.log_table(table, header, table_name="affiliates", max_log_entries=50)

    def add_affiliate(self, event):
        if event.scope_distance > 0 and event.host and isinstance(event.host, str):
            subdomain, domain = self.helpers.split_domain(event.host)
            weight = (1 / event.scope_distance) + (1 if "affiliate" in event.tags else 0)
            if domain and not self.scan.in_scope(domain):
                try:
                    self.affiliates[domain]["weight"] += weight
                    self.affiliates[domain]["count"] += 1
                except KeyError:
                    self.affiliates[domain] = {}
                    self.affiliates[domain]["weight"] = weight
                    self.affiliates[domain]["count"] = 1
