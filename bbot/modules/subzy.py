import json
from pathlib import Path

from bbot.modules.base import BaseModule


class subzy(BaseModule):
    watched_events = ["DNS_NAME", "DNS_NAME_UNRESOLVED"]
    produced_events = ["VULNERABILITY"]
    flags = ["active", "safe", "subdomain-hijack"]
    meta = {
        "description": "Check potential subdomain takeovers with subzy",
        "created_date": "2026-02-20",
        "author": "@carlospolop",
    }
    options = {
        "binary": "subzy",
        "concurrency": 25,
        "timeout": 10,
        "https": False,
        "verify_ssl": False,
    }
    options_desc = {
        "binary": "Path to subzy executable",
        "concurrency": "Concurrent checks for subzy",
        "timeout": "Request timeout in seconds",
        "https": "Use HTTPS when protocol is not supplied",
        "verify_ssl": "Only check sites with valid SSL certs",
    }
    _batch_size = 500
    in_scope_only = True

    async def setup(self):
        self.binary = str(self.config.get("binary", "subzy")).strip()
        self.concurrency = int(self.config.get("concurrency", 25))
        self.timeout = int(self.config.get("timeout", 10))
        self.https = bool(self.config.get("https", False))
        self.verify_ssl = bool(self.config.get("verify_ssl", False))
        if "/" in self.binary:
            if not Path(self.binary).is_file():
                return None, f"subzy binary not found at path: {self.binary}"
        elif not self.helpers.which(self.binary):
            return None, f'subzy binary "{self.binary}" was not found in PATH'
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
        output_file = self.helpers.tempfile("", pipe=False)
        try:
            command = [
                self.binary,
                "run",
                "--targets",
                str(targets_file),
                "--output",
                str(output_file),
                "--vuln",
                "--hide_fails",
                "--concurrency",
                str(self.concurrency),
                "--timeout",
                str(self.timeout),
            ]
            if self.https:
                command.append("--https")
            if self.verify_ssl:
                command.append("--verify_ssl")

            await self.run_process(command, _log_stderr=False)

            output_raw = Path(output_file).read_text(errors="ignore").strip()
            if not output_raw:
                return
            try:
                results = json.loads(output_raw)
            except Exception:
                return
            if not isinstance(results, list):
                return

            for result in results:
                if not isinstance(result, dict):
                    continue
                if str(result.get("status", "")).lower() != "vulnerable":
                    continue

                host = str(result.get("subdomain", "")).strip().rstrip(".").lower()
                if not host:
                    continue
                parent_event = parent_by_host.get(host)
                if parent_event is None:
                    continue

                engine = result.get("engine") or result.get("service") or "subzy"
                discussion = result.get("discussion", "")
                documentation = result.get("documentation", "")
                description = f"Subzy reported potential takeover using [{engine}]"
                if discussion:
                    description += f" discussion [{discussion}]"
                if documentation:
                    description += f" documentation [{documentation}]"

                await self.emit_event(
                    {"severity": "MEDIUM", "description": description, "host": host},
                    "VULNERABILITY",
                    parent_event,
                    tags=["takeover", "subzy"],
                    context=f'{{module}} checked "{host}" with subzy and found {{event.type}}',
                )
        finally:
            targets_file.unlink(missing_ok=True)
            output_file.unlink(missing_ok=True)
