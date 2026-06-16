from .baddns import baddns as baddns_module
from bbot.core.config.models import BaseModuleConfig, Field, SeverityLiteral, ConfidenceLiteral


class baddns_direct(baddns_module):
    watched_events = ["URL", "STORAGE_BUCKET"]
    produced_events = ["FINDING"]
    flags = ["safe", "active", "subdomain-enum", "baddns", "cloud-enum"]
    meta = {
        "description": "Check for unusual subdomain / service takeover edge cases that require direct detection",
        "created_date": "2024-01-29",
        "author": "@liquidsec",
    }

    class Config(BaseModuleConfig):
        custom_nameservers: list = Field([], description="Force BadDNS to use a list of custom nameservers")
        min_severity: SeverityLiteral = Field(
            "LOW", description="Minimum severity to emit (INFO, LOW, MEDIUM, HIGH, CRITICAL)"
        )
        min_confidence: ConfidenceLiteral = Field(
            "MEDIUM", description="Minimum confidence to emit (UNKNOWN, LOW, MEDIUM, HIGH, CONFIRMED)"
        )

    module_threads = 8
    deps_pip = ["baddns~=2.4.0"]

    scope_distance_modifier = 1

    def set_modules(self):
        self.enabled_submodules = ["CNAME"]

    async def handle_event(self, event):
        CNAME_direct_module = self.select_modules()[0]
        kwargs = {
            "http_client": self.helpers.blasthttp,
            "dns_client": self.scan.helpers.dns.blastdns,
            "custom_nameservers": self.custom_nameservers,
            "signatures": self.signatures,
            "direct_mode": True,
        }

        CNAME_direct_instance = CNAME_direct_module(str(event.host), **kwargs)
        if await CNAME_direct_instance.dispatch():
            results = CNAME_direct_instance.analyze()
            if results and len(results) > 0:
                for r in results:
                    r_dict = r.to_dict()

                    severity = r_dict["severity"]
                    confidence = r_dict["confidence"]

                    if not self._meets_threshold(severity, confidence):
                        self.debug(f"Skipping result below threshold (severity={severity}, confidence={confidence})")
                        continue

                    data = {
                        "name": f"BadDNS {r_dict['signature']}",
                        "description": f"Possible [{r_dict['signature']}] via direct BadDNS analysis. Indicator: [{r_dict['indicator']}] Trigger: [{r_dict['trigger']}] baddns Module: [{r_dict['module']}]",
                        "host": str(event.host),
                        "severity": severity,
                        "confidence": confidence,
                    }

                    await self.emit_event(
                        data,
                        "FINDING",
                        event,
                        tags=[f"baddns-{CNAME_direct_module.name.lower()}"],
                        context=f'{{module}}\'s "{r_dict["module"]}" module found {{event.type}}: {r_dict["description"]}',
                    )
        await CNAME_direct_instance.cleanup()

    async def filter_event(self, event):
        if event.type == "STORAGE_BUCKET":
            if str(event.module).startswith("bucket_"):
                return False
            self.debug(f"Processing STORAGE_BUCKET for {event.host}")
        if event.type == "URL":
            if event.scope_distance > 0:
                self.debug(
                    f"Rejecting {event.host} due to not being in scope (scope distance: {event.scope_distance})"
                )
                return False
            if "cloudflare" not in event.tags:
                self.debug(f"Rejecting {event.host} due to not being behind Cloudflare")
                return False
            if "status-200" in event.tags or "status-301" in event.tags:
                self.debug(f"Rejecting {event.host} due to lack of non-standard status code")
                return False

            self.debug(f"Passed all checks and is processing {event.host}")
        return True
