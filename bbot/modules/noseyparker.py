import json
from contextlib import suppress

from bbot.modules.templates.code_secret_scanner import code_secret_scanner


class noseyparker(code_secret_scanner):
    watched_events = ["CODE_REPOSITORY", "FILESYSTEM"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["passive", "safe", "code-enum"]
    meta = {
        "description": "Find hardcoded secrets using Nosey Parker",
        "created_date": "2026-02-19",
        "author": "@carlospolop",
    }

    options = {
        "version": "0.24.0",
        "output_folder": "",
        "clone_repositories": True,
    }
    options_desc = {
        "version": "noseyparker version",
        "output_folder": "Folder to clone repositories to. If not specified, repositories are deleted after scanning.",
        "clone_repositories": "Clone CODE_REPOSITORY events before scanning.",
    }
    deps_ansible = [
        {
            "name": "Set noseyparker release target",
            "set_fact": {
                "bbot_noseyparker_target": "{{ 'aarch64-unknown-linux-gnu' if ansible_facts['system'] == 'Linux' and ansible_facts['architecture'] in ['aarch64', 'arm64'] else 'x86_64-unknown-linux-gnu' if ansible_facts['system'] == 'Linux' and ansible_facts['architecture'] in ['x86_64', 'amd64'] else 'aarch64-apple-darwin' if ansible_facts['system'] == 'Darwin' and ansible_facts['architecture'] in ['aarch64', 'arm64'] else 'x86_64-apple-darwin' if ansible_facts['system'] == 'Darwin' and ansible_facts['architecture'] in ['x86_64', 'amd64'] else '' }}"
            },
        },
        {
            "name": "Create noseyparker temp directory",
            "file": {
                "path": "#{BBOT_TEMP}/noseyparker",
                "state": "directory",
                "mode": "0755",
            },
            "when": "bbot_noseyparker_target != ''",
        },
        {
            "name": "Download noseyparker",
            "unarchive": {
                "src": "https://github.com/praetorian-inc/noseyparker/releases/download/v#{BBOT_MODULES_NOSEYPARKER_VERSION}/noseyparker-v#{BBOT_MODULES_NOSEYPARKER_VERSION}-{{ bbot_noseyparker_target }}.tar.gz",
                "dest": "#{BBOT_TEMP}/noseyparker",
                "remote_src": True,
            },
            "when": "bbot_noseyparker_target != ''",
        },
        {
            "name": "Install noseyparker",
            "shell": {
                "cmd": "install -m 0755 \"$(find #{BBOT_TEMP}/noseyparker -type f -name noseyparker | head -n1)\" \"#{BBOT_TOOLS}/noseyparker\""
            },
            "when": "bbot_noseyparker_target != ''",
        },
    ]

    async def iter_findings(self, scan_path, event):
        datastore = self.helpers.temp_filename(extension="np")
        self.helpers.rm_rf(datastore, ignore_errors=True)
        try:
            await self.run_process(["noseyparker", "datastore", "init", "--datastore", str(datastore)])
            await self.run_process(["noseyparker", "scan", "--datastore", str(datastore), str(scan_path)])
            result = await self.run_process(
                ["noseyparker", "report", "--datastore", str(datastore), "--format", "json"],
                _log_stderr=False,
            )
            raw = getattr(result, "stdout", "") or ""
            if not raw:
                return

            with suppress(Exception):
                parsed = json.loads(raw)
                findings = parsed.get("findings", []) if isinstance(parsed, dict) else parsed
                if not isinstance(findings, list):
                    return
                for finding in findings:
                    if not isinstance(finding, dict):
                        continue
                    rule_name = finding.get("rule_name") or finding.get("rule") or "unknown"
                    snippet = finding.get("snippet") or finding.get("match") or finding.get("match_text") or ""
                    if not snippet and isinstance(finding.get("matches"), list) and finding["matches"]:
                        first_match = finding["matches"][0]
                        if isinstance(first_match, dict):
                            snippet = first_match.get("snippet") or first_match.get("match") or ""
                    yield {
                        "description": f"Nosey Parker matched rule [{rule_name}] with snippet [{snippet}]",
                        "verified": False,
                    }
        finally:
            self.helpers.rm_rf(datastore)
