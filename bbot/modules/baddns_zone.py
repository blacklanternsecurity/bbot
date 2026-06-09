from .baddns import baddns as baddns_module
from bbot.core.config.models import BaseModuleConfig, Field, SeverityLiteral, ConfidenceLiteral


class baddns_zone(baddns_module):
    watched_events = ["DNS_NAME"]
    produced_events = ["FINDING"]
    flags = ["safe", "active", "subdomain-enum", "baddns", "cloud-enum"]
    meta = {
        "description": "Check hosts for DNS zone transfers and NSEC walks",
        "created_date": "2024-01-29",
        "author": "@liquidsec",
    }

    class Config(BaseModuleConfig):
        custom_nameservers: list = Field([], description="Force BadDNS to use a list of custom nameservers")
        min_severity: SeverityLiteral = Field(
            "INFO", description="Minimum severity to emit (INFO, LOW, MEDIUM, HIGH, CRITICAL)"
        )
        min_confidence: ConfidenceLiteral = Field(
            "MEDIUM", description="Minimum confidence to emit (UNKNOWN, LOW, MEDIUM, HIGH, CONFIRMED)"
        )

    module_threads = 8
    deps_pip = ["baddns~=2.4.0"]

    def set_modules(self):
        self.enabled_submodules = ["NSEC", "zonetransfer"]

    # minimize nsec records feeding back into themselves
    async def filter_event(self, event):
        if "baddns-nsec" in event.tags or "baddns-nsec" in event.parent.tags:
            return False
        return True
