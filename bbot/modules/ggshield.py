import json
from contextlib import suppress

from bbot.modules.templates.code_secret_scanner import code_secret_scanner


class ggshield(code_secret_scanner):
    watched_events = ["CODE_REPOSITORY", "FILESYSTEM"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["passive", "safe", "code-enum"]
    meta = {
        "description": "Find hardcoded secrets using GitGuardian ggshield",
        "created_date": "2026-02-19",
        "author": "@carlospolop",
    }
    deps_pip = ["ggshield"]

    options = {
        "output_folder": "",
        "clone_repositories": True,
    }
    options_desc = {
        "output_folder": "Folder to clone repositories to. If not specified, repositories are deleted after scanning.",
        "clone_repositories": "Clone CODE_REPOSITORY events before scanning.",
    }

    async def iter_findings(self, scan_path, event):
        command = [
            "ggshield",
            "secret",
            "scan",
            "path",
            "--recursive",
            "--json",
            str(scan_path),
        ]
        result = await self.run_process(command, _log_stderr=False)
        raw = getattr(result, "stdout", "") or ""
        if not raw:
            return

        with suppress(Exception):
            parsed = json.loads(raw)
            entries = parsed if isinstance(parsed, list) else [parsed]
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                incidents = entry.get("policy_breaks", [])
                if not incidents and isinstance(entry.get("secrets"), list):
                    incidents = entry["secrets"]
                if not isinstance(incidents, list):
                    continue

                for incident in incidents:
                    if not isinstance(incident, dict):
                        continue
                    policy = incident.get("policy")
                    if isinstance(policy, dict):
                        policy_name = policy.get("name", "unknown")
                    else:
                        policy_name = policy or "unknown"
                    match = incident.get("match") or incident.get("matches") or ""
                    validity = str(incident.get("validity", "unknown")).lower()
                    verified = validity in ("valid", "active")
                    severity = "High" if verified else "Medium"
                    yield {
                        "description": f"ggshield detected [{policy_name}] with match [{match}]",
                        "verified": verified,
                        "severity": severity,
                    }
