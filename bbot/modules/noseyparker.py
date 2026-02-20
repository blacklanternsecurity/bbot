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
        "output_folder": "",
        "clone_repositories": True,
    }
    options_desc = {
        "output_folder": "Folder to clone repositories to. If not specified, repositories are deleted after scanning.",
        "clone_repositories": "Clone CODE_REPOSITORY events before scanning.",
    }

    async def iter_findings(self, scan_path, event):
        datastore = self.helpers.temp_filename(extension="np")
        self.helpers.mkdir(datastore)
        try:
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
