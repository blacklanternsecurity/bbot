from baddns.base import get_all_modules
from baddns.lib.loader import load_signatures
from .base import BaseModule

import asyncio
import logging

SEVERITY_LEVELS = ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")
CONFIDENCE_LEVELS = ("UNKNOWN", "LOW", "MODERATE", "HIGH", "CONFIRMED")


class baddns(BaseModule):
    watched_events = ["DNS_NAME", "DNS_NAME_UNRESOLVED"]
    produced_events = ["FINDING"]
    flags = ["active", "safe", "web-basic", "baddns", "cloud-enum", "subdomain-hijack"]
    meta = {
        "description": "Check hosts for domain/subdomain takeovers",
        "created_date": "2024-01-18",
        "author": "@liquidsec",
    }
    options = {"custom_nameservers": [], "min_severity": "LOW", "min_confidence": "MODERATE", "enabled_submodules": []}
    options_desc = {
        "custom_nameservers": "Force BadDNS to use a list of custom nameservers",
        "min_severity": "Minimum severity to emit (INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL)",
        "min_confidence": "Minimum confidence to emit (UNKNOWN, LOW, MODERATE, HIGH, CONFIRMED)",
        "enabled_submodules": "A list of submodules to enable. Empty list (default) enables CNAME, TXT and MX Only",
    }
    module_threads = 8
    deps_pip = ["baddns~=2.0.0"]

    def select_modules(self):
        selected_submodules = []
        for m in get_all_modules():
            if m.name in self.enabled_submodules:
                selected_submodules.append(m)
        return selected_submodules

    def set_modules(self):
        self.enabled_submodules = self.config.get("enabled_submodules", [])
        if self.enabled_submodules == []:
            self.enabled_submodules = ["CNAME", "MX", "TXT"]

    def _meets_threshold(self, severity, confidence):
        sev_idx = SEVERITY_LEVELS.index(severity) if severity in SEVERITY_LEVELS else 0
        conf_idx = CONFIDENCE_LEVELS.index(confidence) if confidence in CONFIDENCE_LEVELS else 0
        return sev_idx >= self._min_sev_idx and conf_idx >= self._min_conf_idx

    async def setup(self):
        self.preset.core.logger.include_logger(logging.getLogger("baddns"))
        self.custom_nameservers = self.config.get("custom_nameservers", []) or None
        if self.custom_nameservers:
            self.custom_nameservers = self.helpers.chain_lists(self.custom_nameservers)
        min_severity = self.config.get("min_severity", "LOW").upper()
        min_confidence = self.config.get("min_confidence", "MODERATE").upper()
        if min_severity not in SEVERITY_LEVELS:
            self.warning(f"Invalid min_severity: {min_severity}, defaulting to LOW")
            min_severity = "LOW"
        if min_confidence not in CONFIDENCE_LEVELS:
            self.warning(f"Invalid min_confidence: {min_confidence}, defaulting to MODERATE")
            min_confidence = "MODERATE"
        self._min_sev_idx = SEVERITY_LEVELS.index(min_severity)
        self._min_conf_idx = CONFIDENCE_LEVELS.index(min_confidence)
        self.signatures = load_signatures()
        self.set_modules()
        all_submodules_list = [m.name for m in get_all_modules()]
        for m in self.enabled_submodules:
            if m not in all_submodules_list:
                self.hugewarning(
                    f"Selected BadDNS submodule [{m}] does not exist. Available submodules: [{','.join(all_submodules_list)}]"
                )
                return False
        self.debug(f"Enabled BadDNS Submodules: [{','.join(self.enabled_submodules)}]")
        return True

    async def handle_event(self, event):
        tasks = []
        for ModuleClass in self.select_modules():
            kwargs = {
                "http_client_class": self.scan.helpers.web.AsyncClient,
                "dns_client": self.scan.helpers.dns.resolver,
                "custom_nameservers": self.custom_nameservers,
                "signatures": self.signatures,
            }

            if ModuleClass.name == "NS":
                kwargs["raw_query_max_retries"] = 1
                kwargs["raw_query_timeout"] = 5.0
                kwargs["raw_query_retry_wait"] = 0

            module_instance = ModuleClass(event.data, **kwargs)
            task = asyncio.create_task(module_instance.dispatch())
            tasks.append((module_instance, task))

        async for completed_task in self.helpers.as_completed([task for _, task in tasks]):
            module_instance = next((m for m, t in tasks if t == completed_task), None)
            try:
                task_result = await completed_task
            except Exception as e:
                self.warning(f"Task for {module_instance} raised an error: {e}")
                task_result = None

            if task_result:
                results = module_instance.analyze()
                if results and len(results) > 0:
                    for r in results:
                        r_dict = r.to_dict()

                        confidence = r_dict["confidence"]
                        severity = r_dict["severity"]

                        if not self._meets_threshold(severity, confidence):
                            self.debug(
                                f"Skipping result below threshold (severity={severity}, confidence={confidence})"
                            )
                            continue

                        data = {
                            "severity": severity,
                            "name": f"BadDNS {r_dict['signature']}",
                            "confidence": confidence,
                            "description": f"{r_dict['description']}. Confidence: [{confidence}] Signature: [{r_dict['signature']}] Indicator: [{r_dict['indicator']}] Trigger: [{r_dict['trigger']}] baddns Module: [{r_dict['module']}]",
                            "host": str(event.host),
                        }
                        await self.emit_event(
                            data,
                            "FINDING",
                            event,
                            tags=[f"baddns-{module_instance.name.lower()}"],
                            context=f'{{module}}\'s "{r_dict["module"]}" module found {{event.type}}: {r_dict["description"]}',
                        )

                        found_domains = r_dict.get("found_domains", None)
                        if found_domains:
                            for found_domain in found_domains:
                                await self.emit_event(
                                    found_domain,
                                    "DNS_NAME",
                                    event,
                                    tags=[f"baddns-{module_instance.name.lower()}"],
                                    context=f'{{module}}\'s "{r_dict["module"]}" module found {{event.type}}: {{event.data}}',
                                )
                await module_instance.cleanup()
