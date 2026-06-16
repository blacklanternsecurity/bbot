from baddns.base import get_all_modules
from baddns.lib.loader import load_signatures
from .base import BaseModule

import logging
from pydantic import Field
from bbot.core.config.models import BaseModuleConfig, SeverityLiteral, ConfidenceLiteral

SEVERITY_LEVELS = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
CONFIDENCE_LEVELS = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CONFIRMED")

SUBMODULE_MAX_SEVERITY = {
    "CNAME": "MEDIUM",
    "NS": "MEDIUM",
    "MX": "MEDIUM",
    "TXT": "LOW",
    "references": "MEDIUM",
    "NSEC": "INFO",
    "zonetransfer": "INFO",
    "DMARC": "INFO",
    "SPF": "MEDIUM",
    "MTA-STS": "HIGH",
    "WILDCARD": "HIGH",
}

SUBMODULE_MAX_CONFIDENCE = {
    "CNAME": "CONFIRMED",
    "NS": "HIGH",
    "MX": "CONFIRMED",
    "TXT": "CONFIRMED",
    "references": "CONFIRMED",
    "NSEC": "CONFIRMED",
    "zonetransfer": "CONFIRMED",
    "DMARC": "CONFIRMED",
    "SPF": "CONFIRMED",
    "MTA-STS": "CONFIRMED",
    "WILDCARD": "CONFIRMED",
}


class baddns(BaseModule):
    watched_events = ["DNS_NAME", "DNS_NAME_UNRESOLVED"]
    produced_events = ["FINDING"]
    flags = ["safe", "active", "web", "baddns", "cloud-enum", "subdomain-hijack"]
    meta = {
        "description": "Check hosts for domain/subdomain takeovers",
        "created_date": "2024-01-18",
        "author": "@liquidsec",
    }

    class Config(BaseModuleConfig):
        custom_nameservers: list[str] = Field(
            default_factory=list, description="Force BadDNS to use a list of custom nameservers"
        )
        min_severity: SeverityLiteral = Field("LOW", description="Minimum severity to emit")
        min_confidence: ConfidenceLiteral = Field("MEDIUM", description="Minimum confidence to emit")
        enabled_submodules: list[str] = Field(
            default_factory=list,
            description="A list of submodules to enable. Empty list (default) enables CNAME, TXT and MX Only",
        )

    module_threads = 8
    deps_pip = ["baddns~=2.4.0"]

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

    def _filter_submodules(self):
        filtered = []
        for name in self.enabled_submodules:
            max_sev = SUBMODULE_MAX_SEVERITY.get(name)
            max_conf = SUBMODULE_MAX_CONFIDENCE.get(name)
            if max_sev is None or max_conf is None:
                filtered.append(name)
                continue
            sev_idx = SEVERITY_LEVELS.index(max_sev) if max_sev in SEVERITY_LEVELS else 0
            conf_idx = CONFIDENCE_LEVELS.index(max_conf) if max_conf in CONFIDENCE_LEVELS else 0
            if sev_idx < self._min_sev_idx or conf_idx < self._min_conf_idx:
                self.verbose(
                    f"Auto-disabling submodule [{name}]: max_severity={max_sev}, max_confidence={max_conf} below configured thresholds"
                )
            else:
                filtered.append(name)
        return filtered

    def _meets_threshold(self, severity, confidence):
        sev_idx = SEVERITY_LEVELS.index(severity) if severity in SEVERITY_LEVELS else 0
        conf_idx = CONFIDENCE_LEVELS.index(confidence) if confidence in CONFIDENCE_LEVELS else 0
        return sev_idx >= self._min_sev_idx and conf_idx >= self._min_conf_idx

    async def setup(self):
        self.preset.core.logger.include_logger(logging.getLogger("baddns"))
        self.custom_nameservers = self.config.get("custom_nameservers", []) or None
        if self.custom_nameservers:
            self.custom_nameservers = self.helpers.chain_lists(self.custom_nameservers)
        min_severity = self.config.get("min_severity").upper()
        min_confidence = self.config.get("min_confidence").upper()
        # guard the unvalidated programmatic path (Scanner(config=...) skips validation)
        if min_severity not in SEVERITY_LEVELS:
            return False, f"Invalid min_severity {min_severity!r}; must be one of {', '.join(SEVERITY_LEVELS)}"
        if min_confidence not in CONFIDENCE_LEVELS:
            return False, f"Invalid min_confidence {min_confidence!r}; must be one of {', '.join(CONFIDENCE_LEVELS)}"
        self._min_sev_idx = SEVERITY_LEVELS.index(min_severity)
        self._min_conf_idx = CONFIDENCE_LEVELS.index(min_confidence)
        self.signatures = load_signatures()
        self.set_modules()
        self.enabled_submodules = self._filter_submodules()
        if not self.enabled_submodules:
            self.warning("All submodules were disabled by severity/confidence thresholds")
            return False
        all_submodules_list = [m.name for m in get_all_modules()]
        for m in self.enabled_submodules:
            if m not in all_submodules_list:
                self.hugewarning(
                    f"Selected BadDNS submodule [{m}] does not exist. Available submodules: [{','.join(all_submodules_list)}]"
                )
                return False
        self.debug(f"Enabled BadDNS Submodules: [{','.join(self.enabled_submodules)}]")
        return True

    async def _run_module(self, module_instance):
        """Wrapper coroutine that runs a module and returns both the module and result"""
        try:
            result = await module_instance.dispatch()
            return module_instance, result
        except Exception as e:
            self.warning(f"Task for {module_instance} raised an error: {e}")
            return module_instance, None

    async def handle_event(self, event):
        coroutines = []
        for ModuleClass in self.select_modules():
            kwargs = {
                "http_client": self.helpers.blasthttp,
                "dns_client": self.scan.helpers.dns.blastdns,
                "custom_nameservers": self.custom_nameservers,
                "signatures": self.signatures,
            }

            if ModuleClass.name == "NS":
                kwargs["raw_query_max_retries"] = 1
                kwargs["raw_query_timeout"] = 5.0
                kwargs["raw_query_retry_wait"] = 0

            module_instance = ModuleClass(event.data, **kwargs)
            # Create wrapper coroutine that includes the module instance
            coroutine = self._run_module(module_instance)
            coroutines.append(coroutine)

        async for completed_coro in self.helpers.as_completed(coroutines):
            try:
                module_instance, task_result = await completed_coro
            except Exception as e:
                self.warning(f"Wrapper coroutine raised an error: {e}")
                continue

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
                                    context=f'{{module}}\'s "{r_dict["module"]}" module found {{event.type}}: {{event.pretty_string}}',
                                )
            await module_instance.cleanup()
