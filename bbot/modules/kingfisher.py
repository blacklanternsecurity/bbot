import json
from contextlib import suppress

from bbot.modules.templates.code_secret_scanner import code_secret_scanner


class kingfisher(code_secret_scanner):
    watched_events = ["CODE_REPOSITORY", "FILESYSTEM"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["passive", "safe", "code-enum"]
    meta = {
        "description": "Find hardcoded secrets using Kingfisher",
        "created_date": "2026-02-19",
        "author": "@carlospolop",
    }

    options = {
        "output_folder": "",
        "clone_repositories": True,
    }
    options_desc = {
        "output_folder": "Folder to clone repositories to. If not specified, repositories are deleted after scanning.",
        "clone_repositories": "Clone CODE_REPOSITORY events before scanning.",
    }

    async def iter_findings(self, scan_path, event):
        command_variants = [
            ["kingfisher", "scan", str(scan_path), "--format", "json"],
            ["kingfisher", "scan", "--path", str(scan_path), "--format", "json"],
        ]
        for command in command_variants:
            result = await self.run_process(command, _log_stderr=False)
            raw = getattr(result, "stdout", "") or ""
            if not raw:
                continue
            with suppress(Exception):
                parsed = json.loads(raw)
                findings = parsed.get("findings", []) if isinstance(parsed, dict) else parsed
                if not isinstance(findings, list):
                    continue
                for finding in findings:
                    if not isinstance(finding, dict):
                        continue
                    detector = finding.get("detector") or finding.get("rule") or "unknown"
                    match = finding.get("match") or finding.get("secret") or ""
                    verified = bool(finding.get("verified", False))
                    severity = "High" if verified else "Medium"
                    yield {
                        "description": f"Kingfisher detected [{detector}] with match [{match}]",
                        "verified": verified,
                        "severity": severity,
                    }
                return
