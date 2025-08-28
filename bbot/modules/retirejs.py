import json
from enum import IntEnum
from bbot.modules.base import BaseModule


class RetireJSSeverity(IntEnum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_string(cls, severity_str):
        try:
            return cls[severity_str.upper()]
        except (KeyError, AttributeError):
            return cls.NONE


class retirejs(BaseModule):
    watched_events = ["URL_UNVERIFIED"]
    produced_events = ["FINDING"]
    flags = ["active", "safe", "web-thorough"]
    meta = {
        "description": "Detect vulnerable/out-of-date JavaScript libraries",
        "created_date": "2025-08-19",
        "author": "@liquidsec",
    }
    options = {
        "node_version": "18.19.1",
        "severity": "medium",
    }
    options_desc = {
        "node_version": "Node.js version to install locally",
        "severity": "Minimum severity level to report (none, low, medium, high, critical)",
    }

    deps_ansible = [
        # Download Node.js binary (Linux x64)
        {
            "name": "Download Node.js binary (Linux x64)",
            "get_url": {
                "url": "https://nodejs.org/dist/v#{BBOT_MODULES_RETIREJS_NODE_VERSION}/node-v#{BBOT_MODULES_RETIREJS_NODE_VERSION}-linux-x64.tar.xz",
                "dest": "#{BBOT_TEMP}/node-v#{BBOT_MODULES_RETIREJS_NODE_VERSION}-linux-x64.tar.xz",
                "mode": "0644",
            },
        },
        # Extract Node.js binary (x64)
        {
            "name": "Extract Node.js binary (x64)",
            "unarchive": {
                "src": "#{BBOT_TEMP}/node-v#{BBOT_MODULES_RETIREJS_NODE_VERSION}-linux-x64.tar.xz",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        },
        # Remove existing node directory if it exists
        {
            "name": "Remove existing node directory",
            "file": {"path": "#{BBOT_TOOLS}/node", "state": "absent"},
        },
        # Rename extracted directory to 'node' (x64)
        {
            "name": "Rename Node.js directory (x64)",
            "command": "mv #{BBOT_TOOLS}/node-v#{BBOT_MODULES_RETIREJS_NODE_VERSION}-linux-x64 #{BBOT_TOOLS}/node",
        },
        # Set permissions on entire Node.js bin directory
        {
            "name": "Set permissions on Node.js bin directory",
            "file": {"path": "#{BBOT_TOOLS}/node/bin", "mode": "0755", "recurse": "yes"},
        },
        # Make Node.js binary executable
        {
            "name": "Make Node.js binary executable",
            "file": {"path": "#{BBOT_TOOLS}/node/bin/node", "mode": "0755"},
        },
        # Make npm executable
        {
            "name": "Make npm executable",
            "file": {"path": "#{BBOT_TOOLS}/node/bin/npm", "mode": "0755"},
        },
        # Remove existing retirejs directory if it exists
        {
            "name": "Remove existing retirejs directory",
            "file": {"path": "#{BBOT_TOOLS}/retirejs", "state": "absent"},
        },
        # Create retire.js local directory
        {
            "name": "Create retire.js directory",
            "file": {"path": "#{BBOT_TOOLS}/retirejs", "state": "directory", "mode": "0755"},
        },
        # Create retire cache directory
        {
            "name": "Create retire cache directory",
            "file": {"path": "#{BBOT_CACHE}/retire_cache", "state": "directory", "mode": "0755"},
        },
    ]

    accept_url_special = True
    scope_distance_modifier = 1
    _module_threads = 4

    async def setup(self):
        excavate_enabled = self.scan.config.get("excavate")
        if not excavate_enabled:
            return None, "retirejs will not function without excavate enabled"

        # Validate severity level
        valid_severities = ["none", "low", "medium", "high", "critical"]
        configured_severity = self.config.get("severity", "medium").lower()
        if configured_severity not in valid_severities:
            return (
                False,
                f"Invalid severity level '{configured_severity}'. Valid options are: {', '.join(valid_severities)}",
            )

        # Download Retire.js repository JSON
        self.repofile = await self.helpers.download(
            "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json", cache_hrs=24
        )
        if not self.repofile:
            return False, "failed to download retire.js repository file"

        # Ensure Retire.js is installed/updated
        await self.ensure_latest_retire()

        return True

    async def ensure_latest_retire(self):
        retire_dir = self.scan.helpers.tools_dir / "retirejs"
        retire_dir.mkdir(parents=True, exist_ok=True)

        local_node_dir = self.scan.helpers.tools_dir / "node"
        retire_cli_script = retire_dir / "node_modules" / ".bin" / "retire"

        install_cmd = [
            str(local_node_dir / "bin" / "npm"),
            "install",
            "retire",
            "--prefix",
            str(retire_dir),
            "--no-fund",
            "--no-audit",
            "--no-optional",
        ]

        self.verbose(f"Installing/updating Retire.js with command: {install_cmd}")
        await self.run_process(install_cmd, shell=False)

        # Fix shebang in retire executable
        retire_executable = retire_dir / "node_modules" / ".bin" / "retire"
        if retire_executable.exists():
            fix_shebang_cmd = [
                "sed",
                "-i",
                f"1s|#!/usr/bin/env node|#!{local_node_dir}/bin/node|",
                str(retire_executable),
            ]
            await self.run_process(fix_shebang_cmd, shell=False)
            retire_executable.chmod(0o755)

    async def handle_event(self, event):
        js_file = await self.helpers.request(event.data)
        if js_file:
            js_file_body = js_file.text
            if js_file_body:
                js_file_body_saved = self.helpers.tempfile(js_file_body, pipe=False, extension="js")
                results = await self.execute_retirejs(js_file_body_saved)
                if not results:
                    self.warning("no output from retire.js")
                    return
                results_json = json.loads(results)
                if results_json.get("data"):
                    for file_result in results_json["data"]:
                        for component_result in file_result.get("results", []):
                            component = component_result.get("component", "unknown")
                            version = component_result.get("version", "unknown")
                            vulnerabilities = component_result.get("vulnerabilities", [])
                            for vuln in vulnerabilities:
                                severity = vuln.get("severity", "unknown")

                                # Filter by minimum severity level
                                min_severity = RetireJSSeverity.from_string(self.config.get("severity", "medium"))
                                vuln_severity = RetireJSSeverity.from_string(severity)
                                if vuln_severity < min_severity:
                                    self.debug(
                                        f"Skipping vulnerability with severity '{severity}' (below minimum '{min_severity.name.lower()}')"
                                    )
                                    continue

                                identifiers = vuln.get("identifiers", {})
                                summary = identifiers.get("summary", "Unknown vulnerability")
                                cves = identifiers.get("CVE", [])
                                description_parts = [
                                    f"Vulnerable JavaScript library detected: {component} v{version}",
                                    f"Severity: {severity.upper()}",
                                    f"Summary: {summary}",
                                    f"JavaScript URL: {event.data}",
                                ]
                                if cves:
                                    description_parts.append(f"CVE(s): {', '.join(cves)}")

                                below_version = vuln.get("below", "")
                                at_or_above = vuln.get("atOrAbove", "")
                                if at_or_above and below_version:
                                    description_parts.append(f"Affected versions: [{at_or_above} to {below_version})")
                                elif below_version:
                                    description_parts.append(f"Affected versions: [< {below_version}]")
                                elif at_or_above:
                                    description_parts.append(f"Affected versions: [>= {at_or_above}]")
                                description = " ".join(description_parts)
                                data = {
                                    "description": description,
                                    "severity": severity,
                                    "component": component,
                                    "url": event.parent.data["url"],
                                }
                                await self.emit_event(
                                    data,
                                    "FINDING",
                                    parent=event,
                                    context=f"{{module}} identified vulnerable JavaScript library {component} v{version} ({severity} severity)",
                                )

    async def filter_event(self, event):
        url_extension = getattr(event, "url_extension", "")
        if url_extension != "js":
            return False, f"it is a {url_extension} URL but retirejs only accepts js URLs"
        return True

    async def execute_retirejs(self, js_file):
        cache_dir = self.helpers.cache_dir / "retire_cache"
        retire_dir = self.scan.helpers.tools_dir / "retirejs"

        retire_cli_script = retire_dir / "node_modules" / ".bin" / "retire"

        command = [
            str(self.scan.helpers.tools_dir / "node" / "bin" / "node"),
            str(retire_cli_script),
            "--outputformat",
            "json",
            "--cachedir",
            str(cache_dir),
            "--path",
            js_file,
            "--jsrepo",
            str(self.repofile),
        ]

        proxy = self.scan.web_config.get("http_proxy")
        if proxy:
            command.extend(["--proxy", proxy])

        self.verbose(f"Running retire.js on {js_file}")
        self.verbose(f"retire.js command: {command}")

        result = await self.run_process(command, shell=False)
        return result.stdout
