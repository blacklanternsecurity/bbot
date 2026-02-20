import json
import subprocess
from urllib.parse import urlparse

from bbot.modules.base import BaseModule


class nuclei_takeover(BaseModule):
    watched_events = ["DNS_NAME", "DNS_NAME_UNRESOLVED"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "safe", "subdomain-hijack"]
    meta = {
        "description": "Run nuclei takeover templates (-tags takeover) against discovered hostnames",
        "created_date": "2026-02-20",
        "author": "@carlospolop",
    }

    options = {
        "version": "3.6.2",
        "tags": "takeover",
        "templates": "",
        "etags": "",
        "ratelimit": 150,
        "concurrency": 25,
        "retries": 1,
        "timeout": 10,
        "silent": True,
    }
    options_desc = {
        "version": "nuclei version",
        "tags": "Nuclei tags to run (default: takeover)",
        "templates": "Optional nuclei templates/template-dirs to include",
        "etags": "Optional nuclei tags to exclude",
        "ratelimit": "Nuclei request rate limit per second",
        "concurrency": "Nuclei template concurrency",
        "retries": "Nuclei retries",
        "timeout": "Nuclei timeout in seconds",
        "silent": "Only show findings output from nuclei",
    }

    deps_ansible = [
        {
            "name": "Download nuclei",
            "unarchive": {
                "src": "https://github.com/projectdiscovery/nuclei/releases/download/v#{BBOT_MODULES_NUCLEI_TAKEOVER_VERSION}/nuclei_#{BBOT_MODULES_NUCLEI_TAKEOVER_VERSION}_#{BBOT_OS}_#{BBOT_CPU_ARCH_GOLANG}.zip",
                "include": "nuclei",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        }
    ]
    _batch_size = 500
    in_scope_only = True

    async def setup(self):
        if not self.helpers.which("nuclei"):
            return None, 'nuclei binary "nuclei" was not found in PATH'
        self.tags = str(self.config.get("tags", "takeover")).strip() or "takeover"
        self.templates = str(self.config.get("templates", "")).strip()
        self.etags = str(self.config.get("etags", "")).strip()
        self.ratelimit = int(self.config.get("ratelimit", 150))
        self.concurrency = int(self.config.get("concurrency", 25))
        self.retries = int(self.config.get("retries", 1))
        self.timeout = int(self.config.get("timeout", 10))
        self.silent = bool(self.config.get("silent", True))
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

        command = [
            "nuclei",
            "-jsonl",
            "-disable-update-check",
            "-tags",
            self.tags,
            "-rate-limit",
            str(self.ratelimit),
            "-concurrency",
            str(self.concurrency),
            "-retries",
            str(self.retries),
            "-timeout",
            str(self.timeout),
        ]
        if self.silent:
            command.append("-silent")
        if self.templates:
            command += ["-t", self.templates]
        if self.etags:
            command += ["-etags", self.etags]
        if self.helpers.system_resolvers:
            command += ["-r", self.helpers.resolver_file]

        async for line in self.run_process_live(command, input=targets, stderr=subprocess.DEVNULL):
            try:
                finding = json.loads(line)
            except Exception:
                continue

            host = self.normalize_host(finding.get("host", "") or finding.get("matched-at", ""))
            if not host:
                continue
            parent_event = parent_by_host.get(host)
            if parent_event is None:
                continue

            info = finding.get("info", {}) if isinstance(finding.get("info"), dict) else {}
            template_id = finding.get("template-id", "unknown")
            name = info.get("name", "unknown")
            matched_at = finding.get("matched-at", "")
            matcher = finding.get("matcher-name", "")
            extracted = finding.get("extracted-results", [])
            if isinstance(extracted, list) and extracted:
                extracted_str = ",".join(str(x) for x in extracted[:8])
            else:
                extracted_str = ""

            description = f'Nuclei takeover match template [{template_id}] name [{name}] at [{matched_at}]'
            if matcher:
                description += f" matcher [{matcher}]"
            if extracted_str:
                description += f" extracted [{extracted_str}]"

            severity = str(info.get("severity", "")).lower().strip()
            event_type = "VULNERABILITY"
            event_data = {"description": description, "host": host}
            if severity in ("info", "unknown", ""):
                event_type = "FINDING"
            else:
                event_data["severity"] = severity.upper()

            await self.emit_event(
                event_data,
                event_type,
                parent_event,
                tags=["takeover", "nuclei-takeover"],
                context=f'{{module}} used nuclei takeover templates and found {{event.type}} on "{host}"',
            )

    @staticmethod
    def normalize_host(value):
        text = str(value or "").strip()
        if not text:
            return ""
        if "://" in text:
            text = urlparse(text).hostname or ""
        else:
            text = text.split("/")[0]
            text = text.split(":")[0]
        return text.strip().rstrip(".").lower()
