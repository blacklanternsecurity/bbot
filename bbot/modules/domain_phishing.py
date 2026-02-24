import json
import re
from datetime import datetime, timezone
from pathlib import Path

from bbot.modules.base import BaseModule


class domain_phishing(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "safe", "subdomain-enum", "phishing"]
    meta = {
        "description": "Detect likely phishing/typosquat domains using dnstwist permutations + heuristics",
        "created_date": "2026-02-24",
        "author": "@carlospolop + @codex",
    }
    options = {
        "binary": "dnstwist",
        "registered_only": True,
        "fuzzers": [
            "addition",
            "bitsquatting",
            "homoglyph",
            "hyphenation",
            "insertion",
            "omission",
            "replacement",
            "transposition",
            "tld-swap",
        ],
        "nameservers": [],
        "threads": 16,
        "lsh": False,
        "lsh_threshold": 70,
        "young_domain_days": 45,
        "max_candidates": 2000,
        "min_score": 3,
    }
    options_desc = {
        "binary": "Path to dnstwist binary",
        "registered_only": "Only analyze registered permutations",
        "fuzzers": "Subset of dnstwist fuzzers to use",
        "nameservers": "Custom resolvers for dnstwist (comma-separated)",
        "threads": "dnstwist worker threads",
        "lsh": "Enable dnstwist LSH page-similarity checks (slower)",
        "lsh_threshold": "If LSH score >= this threshold, increase confidence",
        "young_domain_days": "Registration age in days considered suspicious",
        "max_candidates": "Maximum permutations to evaluate per root domain",
        "min_score": "Minimum score to emit as finding",
    }
    deps_pip = ["dnstwist"]
    in_scope_only = True
    per_domain_only = True

    HIGH_RISK_FUZZERS = {
        "bitsquatting",
        "homoglyph",
        "hyphenation",
        "insertion",
        "omission",
        "replacement",
        "transposition",
        "tld-swap",
        "addition",
    }

    def _pick(self, item, *keys):
        for key in keys:
            if key in item and item.get(key) is not None:
                return item.get(key)
        return None

    def _as_list(self, value):
        if value is None:
            return []
        if isinstance(value, list):
            return [str(v).strip() for v in value if str(v).strip()]
        text = str(value).strip()
        return [text] if text else []

    def _parse_json_output(self, text):
        raw = str(text or "").strip()
        if not raw:
            return []
        # dnstwist might prepend logs, keep only JSON array payload.
        start = raw.find("[")
        end = raw.rfind("]")
        if start == -1 or end == -1 or end <= start:
            return []
        payload = raw[start : end + 1]
        try:
            data = json.loads(payload)
        except Exception:
            return []
        if isinstance(data, list):
            return data
        return []

    def _parse_domain_age_days(self, created):
        if not created:
            return None
        value = str(created).strip()
        if not value:
            return None
        m = re.search(r"(\d{4}-\d{2}-\d{2})", value)
        if m:
            value = m.group(1)
        for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
                return max(0, (datetime.now(timezone.utc) - dt).days)
            except Exception:
                continue
        return None

    def _score_candidate(self, candidate):
        score = 0
        reasons = []

        fuzzer = str(self._pick(candidate, "fuzzer", "fuzz") or "").strip().lower()
        if fuzzer in self.HIGH_RISK_FUZZERS:
            score += 1
            reasons.append(f"high-risk permutation technique ({fuzzer})")

        dns_a = self._as_list(self._pick(candidate, "dns-a", "dns_a"))
        dns_aaaa = self._as_list(self._pick(candidate, "dns-aaaa", "dns_aaaa"))
        dns_mx = self._as_list(self._pick(candidate, "dns-mx", "dns_mx"))
        dns_ns = self._as_list(self._pick(candidate, "dns-ns", "dns_ns"))

        if dns_a or dns_aaaa:
            score += 1
            reasons.append("active A/AAAA records")
        if dns_mx:
            score += 1
            reasons.append("active MX records")
        if dns_ns:
            score += 1
            reasons.append("delegated NS records")

        created = self._pick(candidate, "whois-created", "whois_created", "created")
        age_days = self._parse_domain_age_days(created)
        if age_days is not None and age_days <= self.young_domain_days:
            score += 2
            reasons.append(f"newly registered ({age_days} days old)")

        lsh = self._pick(candidate, "lsh")
        try:
            lsh_value = int(float(str(lsh)))
        except Exception:
            lsh_value = None

        if lsh_value is not None and lsh_value >= self.lsh_threshold:
            score += 3
            reasons.append(f"high page similarity (LSH {lsh_value}%)")

        severity = ""
        if score >= 6:
            severity = "HIGH"
        elif score >= 4:
            severity = "MEDIUM"

        return score, severity, reasons

    async def setup(self):
        self.binary = str(self.config.get("binary", "dnstwist")).strip()
        self.registered_only = bool(self.config.get("registered_only", True))
        self.fuzzers = list(self.config.get("fuzzers", []))
        self.nameservers = list(self.config.get("nameservers", []))
        self.threads = int(self.config.get("threads", 16))
        self.enable_lsh = bool(self.config.get("lsh", False))
        self.lsh_threshold = int(self.config.get("lsh_threshold", 70))
        self.young_domain_days = int(self.config.get("young_domain_days", 45))
        self.max_candidates = int(self.config.get("max_candidates", 2000))
        self.min_score = int(self.config.get("min_score", 3))

        if "/" in self.binary:
            if not Path(self.binary).is_file():
                return None, f"dnstwist binary not found at path: {self.binary}"
        elif not self.helpers.which(self.binary):
            return None, f'dnstwist binary "{self.binary}" was not found in PATH'

        if self.enable_lsh:
            self.info("domain_phishing: LSH similarity checks enabled (slower).")

        return True

    async def handle_event(self, event):
        input_domain = str(event.data or "").strip().lower().rstrip(".")
        if not input_domain:
            return

        _, root_domain = self.helpers.split_domain(input_domain)
        root_domain = str(root_domain or "").strip().lower()
        if not root_domain or not self.helpers.is_domain(root_domain):
            return

        command = [self.binary, "--format", "json", "--threads", str(self.threads)]

        if self.registered_only:
            command.append("--registered")

        if self.enable_lsh:
            command += ["--lsh", "ssdeep"]

        if self.fuzzers:
            command += ["--fuzzers", ",".join(self.fuzzers)]

        if self.nameservers:
            command += ["--nameservers", ",".join(self.nameservers)]

        command.append(root_domain)

        process = await self.run_process(command, _log_stderr=False)
        rows = self._parse_json_output(getattr(process, "stdout", ""))
        if not rows:
            self.debug(f"domain_phishing: no candidates returned by dnstwist for {root_domain}")
            return

        emitted = 0
        for idx, candidate in enumerate(rows):
            if idx >= self.max_candidates:
                break
            if not isinstance(candidate, dict):
                continue

            candidate_domain = str(self._pick(candidate, "domain") or "").strip().lower().rstrip(".")
            if not candidate_domain or candidate_domain == root_domain:
                continue

            # Keep scan scope constrained: report risk as finding/vuln without expanding enumeration.
            score, severity, reasons = self._score_candidate(candidate)
            if score < self.min_score:
                continue

            fuzzer = str(self._pick(candidate, "fuzzer", "fuzz") or "unknown").strip()
            details = f"template: [domain-phishing], name: [Potential phishing look-alike], fuzzer: [{fuzzer}], score: [{score}]"
            if reasons:
                details += f" Extracted Data: [{'; '.join(reasons)}]"

            tags = ["phishing", "typosquatting", f"fuzzer-{fuzzer.lower()}"]

            payload = {
                "host": candidate_domain,
                "description": details,
            }

            event_type = "FINDING"
            if severity:
                event_type = "VULNERABILITY"
                payload["severity"] = severity

            await self.emit_event(
                payload,
                event_type,
                parent=event,
                tags=tags,
                context=f'{{module}} analyzed "{root_domain}" permutations and found {{event.type}} on look-alike domain "{candidate_domain}"',
            )
            emitted += 1

        self.info(f"domain_phishing: emitted {emitted} phishing candidate events for {root_domain}")
