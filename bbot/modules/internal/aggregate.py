from bbot.modules.internal.base import BaseInternalModule


class aggregate(BaseInternalModule):
    watched_events = ["*"]
    produced_events = ["AFFILIATE"]
    scope_distance_modifier = None

    def setup(self):
        self.affiliates = {}
        return True

    def handle_event(self, event):
        self.add_affiliate(event)

    def report(self):
        affiliates = sorted(self.affiliates.items(), key=lambda x: x[-1]["weight"], reverse=True)
        for domain, stats in affiliates:
            count = stats["count"]
            weight = stats["weight"]
            self.emit_event(
                f"{domain} (count: {count:,}, weight: {weight:.1f})", "AFFILIATE", source=self.scan.root_event
            )

    def add_affiliate(self, event):
        if event.scope_distance > 0 and event.host and isinstance(event.host, str):
            subdomain, domain = self.helpers.split_domain(event.host)
            weight = 1 / event.scope_distance
            try:
                self.affiliates[domain]["weight"] += weight
                self.affiliates[domain]["count"] += 1
            except KeyError:
                self.affiliates[domain] = {}
                self.affiliates[domain]["weight"] = weight
                self.affiliates[domain]["count"] = 1
