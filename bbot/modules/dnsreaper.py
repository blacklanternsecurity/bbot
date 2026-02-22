import json
from pathlib import Path

from bbot.modules.base import BaseModule


class dnsreaper(BaseModule):
    watched_events = ["DNS_NAME", "DNS_NAME_UNRESOLVED"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "safe", "subdomain-hijack"]
    meta = {
        "description": "Check potential subdomain takeovers with dnsReaper",
        "created_date": "2026-02-20",
        "author": "@carlospolop",
    }
    options = {
        "version": "2.0.3",
        "binary": "dnsreaper",
        "parallelism": 30,
        "resolver": "",
        "disable_probable": False,
        "enable_unlikely": False,
        "signatures": [],
        "exclude_signatures": [],
    }
    options_desc = {
        "version": "dnsreaper version",
        "binary": "Path to dnsreaper executable",
        "parallelism": "Number of domains to test in parallel",
        "resolver": "Optional custom resolver list (comma separated)",
        "disable_probable": "Skip potential/probable findings",
        "enable_unlikely": "Enable unlikely confidence findings",
        "signatures": "Only run these signatures",
        "exclude_signatures": "Exclude these signatures",
    }
    _batch_size = 500
    in_scope_only = True
    deps_ansible = [
        {
            "name": "Install python venv",
            "package": {"name": ["python3-venv"], "state": "present"},
            "become": True,
            "ignore_errors": True,
        },
        {
            "name": "Clone dnsReaper repository",
            "git": {
                "repo": "https://github.com/punk-security/dnsReaper",
                "dest": "#{BBOT_TEMP}/dnsreaper",
                "version": "#{BBOT_MODULES_DNSREAPER_VERSION}",
            },
        },
        {
            "name": "Create dnsreaper venv",
            "command": {
                "cmd": "python3 -m venv .venv",
                "chdir": "#{BBOT_TEMP}/dnsreaper",
                "creates": "#{BBOT_TEMP}/dnsreaper/.venv/bin/python",
            },
        },
        {
            "name": "Install dnsreaper requirements",
            "command": {
                "cmd": ".venv/bin/pip install -r requirements.txt",
                "chdir": "#{BBOT_TEMP}/dnsreaper",
            },
        },
        {
            "name": "Install dnsreaper wrapper",
            "copy": {
                "dest": "#{BBOT_TOOLS}/dnsreaper",
                "mode": "u+x,g+x,o+x",
                "content": "#!/usr/bin/env bash\nexec \"#{BBOT_TEMP}/dnsreaper/.venv/bin/python\" \"#{BBOT_TEMP}/dnsreaper/main.py\" \"$@\"\n",
            },
        },
    ]

    async def setup(self):
        self.binary = str(self.config.get("binary", "dnsreaper")).strip()
        self.parallelism = int(self.config.get("parallelism", 30))
        self.resolver = str(self.config.get("resolver", "")).strip()
        self.disable_probable = bool(self.config.get("disable_probable", False))
        self.enable_unlikely = bool(self.config.get("enable_unlikely", False))
        self.signatures = self.helpers.chain_lists(self.config.get("signatures", []))
        self.exclude_signatures = self.helpers.chain_lists(self.config.get("exclude_signatures", []))
        if "/" in self.binary:
            if not Path(self.binary).is_file():
                return None, f"dnsreaper binary not found at path: {self.binary}"
        elif not self.helpers.which(self.binary):
            return None, f'dnsreaper binary "{self.binary}" was not found in PATH'
        return True

    async def handle_batch(self, *events):
        targets = []
        parent_by_host = {}
        for event in events:
            host = str(event.host or "").strip().rstrip(".").lower()
            if not host:
                continue
            if host not in parent_by_host:
                parent_by_host[host] = event
                targets.append(host)

        if not targets:
            return

        targets_file = self.helpers.tempfile(targets, pipe=False)
        try:
            command = [
                self.binary,
                "file",
                "--filename",
                str(targets_file),
                "--out",
                "stdout",
                "--out-format",
                "json",
                "--parallelism",
                str(self.parallelism),
                "--nocolour",
            ]
            if self.resolver:
                command += ["--resolver", self.resolver]
            if self.disable_probable:
                command.append("--disable-probable")
            if self.enable_unlikely:
                command.append("--enable-unlikely")
            for signature in self.signatures:
                command += ["--signature", str(signature)]
            for signature in self.exclude_signatures:
                command += ["--exclude-signature", str(signature)]

            result = await self.run_process(command, _log_stderr=False)
            raw = str(getattr(result, "stdout", "") or "").strip()
            if not raw:
                return
            try:
                findings = json.loads(raw)
            except Exception:
                return
            if not isinstance(findings, list):
                return

            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                host = str(finding.get("domain", "")).strip().rstrip(".").lower()
                if not host:
                    continue
                parent_event = parent_by_host.get(host)
                if parent_event is None:
                    continue

                signature = finding.get("signature", "unknown")
                confidence = str(finding.get("confidence", "UNKNOWN")).upper()
                info = finding.get("info", "")
                more_info_url = finding.get("more_info_url", "")

                description = f"dnsReaper signature [{signature}] confidence [{confidence}]"
                if info:
                    description += f" info [{info}]"
                if more_info_url:
                    description += f" reference [{more_info_url}]"

                if confidence == "UNLIKELY":
                    await self.emit_event(
                        {"description": description, "host": host},
                        "FINDING",
                        parent_event,
                        tags=["takeover", "dnsreaper"],
                        context=f'{{module}} checked "{host}" with dnsReaper and found {{event.type}}',
                    )
                else:
                    severity = "HIGH" if confidence == "CONFIRMED" else "MEDIUM"
                    await self.emit_event(
                        {"severity": severity, "description": description, "host": host},
                        "VULNERABILITY",
                        parent_event,
                        tags=["takeover", "dnsreaper"],
                        context=f'{{module}} checked "{host}" with dnsReaper and found {{event.type}}',
                    )
        finally:
            targets_file.unlink(missing_ok=True)
