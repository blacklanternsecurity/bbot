import json
from contextlib import suppress

from bbot.modules.templates.code_secret_scanner import code_secret_scanner


class gitleaks(code_secret_scanner):
    watched_events = ["CODE_REPOSITORY", "FILESYSTEM"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["passive", "safe", "code-enum"]
    meta = {
        "description": "Find hardcoded secrets using Gitleaks",
        "created_date": "2026-02-19",
        "author": "@carlospolop",
    }

    options = {
        "version": "8.30.0",
        "config": "",
        "redact": True,
        "output_folder": "",
        "clone_repositories": True,
    }
    options_desc = {
        "version": "gitleaks version",
        "config": "File path or URL to a Gitleaks TOML config",
        "redact": "Redact secrets in command output/report",
        "output_folder": "Folder to clone repositories to. If not specified, repositories are deleted after scanning.",
        "clone_repositories": "Clone CODE_REPOSITORY events before scanning.",
    }
    deps_ansible = [
        {
            "name": "Set gitleaks architecture",
            "set_fact": {
                "bbot_gitleaks_arch": "{{ 'x64' if ansible_facts['architecture'] in ['x86_64', 'amd64'] else 'arm64' if ansible_facts['architecture'] in ['aarch64', 'arm64'] else ansible_facts['architecture'] }}"
            },
        },
        {
            "name": "Download gitleaks",
            "unarchive": {
                "src": "https://github.com/gitleaks/gitleaks/releases/download/v#{BBOT_MODULES_GITLEAKS_VERSION}/gitleaks_#{BBOT_MODULES_GITLEAKS_VERSION}_#{BBOT_OS_PLATFORM}_{{ bbot_gitleaks_arch }}.tar.gz",
                "include": "gitleaks",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        },
    ]

    async def setup_deps(self):
        self.config_file = self.config.get("config", "")
        if self.config_file:
            self.config_file = await self.helpers.wordlist(self.config_file)
        return True

    async def setup(self):
        self.redact = bool(self.config.get("redact", True))
        return await super().setup()

    async def iter_findings(self, scan_path, event):
        report_file = self.helpers.temp_filename(extension="json")

        try:
            # Preferred CLI for newer versions.
            command = [
                "gitleaks",
                "dir",
                str(scan_path),
                "--report-format",
                "json",
                "--report-path",
                str(report_file),
                "--exit-code",
                "0",
                "--no-banner",
            ]
            if self.redact:
                command.append("--redact")
            if self.config_file:
                command.extend(["--config", str(self.config_file)])

            result = await self.run_process(command)

            # Backward-compatible fallback used by older versions.
            if getattr(result, "returncode", 0) != 0 and not report_file.is_file():
                fallback = [
                    "gitleaks",
                    "detect",
                    "--source",
                    str(scan_path),
                    "--report-format",
                    "json",
                    "--report-path",
                    str(report_file),
                    "--exit-code",
                    "0",
                    "--no-banner",
                ]
                if self.redact:
                    fallback.append("--redact")
                if self.config_file:
                    fallback.extend(["--config", str(self.config_file)])
                await self.run_process(fallback)

            with suppress(Exception):
                raw = report_file.read_text(encoding="utf-8", errors="ignore")
                parsed = json.loads(raw)
                findings = parsed.get("findings", []) if isinstance(parsed, dict) else parsed
                if isinstance(findings, list):
                    for finding in findings:
                        if not isinstance(finding, dict):
                            continue
                        rule = finding.get("RuleID") or finding.get("rule") or "unknown"
                        file_name = finding.get("File") or finding.get("file") or str(scan_path)
                        line = finding.get("StartLine") or finding.get("line") or "?"
                        secret = finding.get("Secret") or finding.get("Match") or "<redacted>"
                        yield {
                            "description": f"Gitleaks detected secret rule [{rule}] in [{file_name}:{line}] secret [{secret}]",
                            "verified": False,
                        }
        finally:
            report_file.unlink(missing_ok=True)
