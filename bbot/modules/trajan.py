import json
from urllib.parse import urlparse

from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class trajan(BaseModule):
    watched_events = ["CODE_REPOSITORY", "URL_UNVERIFIED", "TECHNOLOGY"]
    produced_events = ["FINDING"]
    flags = ["safe", "passive", "code-enum"]
    meta = {
        "description": "Scans GitHub, GitLab, Azure DevOps, Jenkins, and JFrog for misconfigurations using Praetorian's Trajan tool",
        "created_date": "2026-04-11",
        "author": "@N7WERA",
    }

    # Configuration options
    class Config(BaseModuleConfig):
        version: str = Field("1.0.0", description="Trajan version to download and use")
        github_token: str = Field(
            "", description="GitHub API token for rate-limiting and private repo access", sensitive=True
        )
        gitlab_token: str = Field("", description="GitLab API token for private repo access", sensitive=True)
        ado_token: str = Field("", description="Azure DevOps Personal Access Token (PAT)", sensitive=True)
        jfrog_token: str = Field("", description="JFrog API token", sensitive=True)
        jenkins_username: str = Field("", description="Jenkins username for basic auth", sensitive=True)
        jenkins_password: str = Field("", description="Jenkins password for basic auth", sensitive=True)
        jenkins_token: str = Field("", description="Jenkins API token", sensitive=True)

    deps_ansible = [
        {
            "name": "Download Trajan binary",
            "unarchive": {
                "src": "https://github.com/praetorian-inc/trajan/releases/download/v#{BBOT_MODULES_TRAJAN_VERSION}/trajan_#{BBOT_MODULES_TRAJAN_VERSION}_#{BBOT_OS}_#{BBOT_CPU_ARCH_GOLANG}.tar.gz",
                "include": "trajan",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        }
    ]

    # Platform detection from URL domains (SaaS platforms)
    domain_platforms = {
        "github.com": "github",
        "gitlab.com": "gitlab",
        "jfrog.com": "jfrog",
        "jfrog.io": "jfrog",
    }

    # Platform detection from TECHNOLOGY event names (lowercased)
    technology_platforms = {
        "jenkins": "jenkins",
        "jfrog": "jfrog",
        "artifactory": "jfrog",
    }

    async def setup(self):
        self.github_token = self.config.get("github_token", "")

        # Borrow GitHub token from other modules if not explicitly set
        if not self.github_token:
            for module_name in ("github", "github_codesearch", "github_org", "git_clone"):
                other_config = self.scan.config.get("modules", {}).get(module_name, {})
                api_key = other_config.get("api_key", "")
                if api_key:
                    self.github_token = api_key
                    self.debug(f"Borrowing GitHub token from {module_name}")
                    break

        self.gitlab_token = self.config.get("gitlab_token", "")
        self.ado_token = self.config.get("ado_token", "")
        self.jfrog_token = self.config.get("jfrog_token", "")
        self.jenkins_username = self.config.get("jenkins_username", "")
        self.jenkins_password = self.config.get("jenkins_password", "")
        self.jenkins_token = self.config.get("jenkins_token", "")
        if self.jenkins_token or (self.jenkins_username and self.jenkins_password):
            self.warning(
                "Jenkins credentials are configured. These will be sent to ANY in-scope server detected as Jenkins!"
            )
        return True

    def detect_platform_from_url(self, hostname, domain):
        """Detect platform from URL hostname/domain."""
        if domain == "azure.com" and hostname.startswith("dev."):
            return "ado"
        return self.domain_platforms.get(domain)

    def detect_platform_from_technology(self, technology):
        """Detect platform from a TECHNOLOGY event's technology name."""
        return self.technology_platforms.get(technology.lower())

    def _get_platform(self, event):
        """Detect the platform for an event, or None if not applicable."""
        if event.type == "TECHNOLOGY":
            tech = event.data.get("technology", "").lower()
            return self.detect_platform_from_technology(tech)
        hostname = str(event.host)
        _, domain = self.helpers.split_domain(hostname)
        return self.detect_platform_from_url(hostname, domain)

    def _incoming_dedup_hash(self, event):
        platform = self._get_platform(event)
        return hash(f"{platform}:{event.host}"), f"already scanned {event.host} as {platform}"

    async def filter_event(self, event):
        if event.type == "TECHNOLOGY":
            tech = event.data.get("technology", "").lower()
            if tech not in self.technology_platforms:
                return False, f"technology '{tech}' is not supported by trajan"
            if not event.url:
                return False, "TECHNOLOGY event has no URL"

        platform = self._get_platform(event)
        if platform is None:
            return False, "could not determine platform from event"
        return True

    async def handle_event(self, event):
        if event.type == "TECHNOLOGY":
            await self.handle_technology(event)
        else:
            await self.handle_url(event)

    async def handle_technology(self, event):
        tech = event.data.get("technology", "").lower()
        platform = self.detect_platform_from_technology(tech)
        url = event.url
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        path_parts = [p for p in parsed.path.strip("/").split("/") if p]

        handler = getattr(self, f"handle_{platform}", None)
        if handler:
            await handler(event, parsed, base_url, path_parts)

    async def handle_url(self, event):
        parsed = getattr(event, "parsed_url", None)
        hostname = parsed.hostname
        _, domain = self.helpers.split_domain(hostname)
        platform = self.detect_platform_from_url(hostname, domain)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        path_parts = [p for p in parsed.path.strip("/").split("/") if p]

        handler = getattr(self, f"handle_{platform}", None)
        if handler:
            await handler(event, parsed, base_url, path_parts)

    async def handle_github(self, event, parsed, base_url, path_parts):
        if not self.github_token:
            self.warning(f"Skipping {base_url} - GitHub token required for Trajan")
            return
        if len(path_parts) < 2:
            return
        repo_path = f"{path_parts[0]}/{path_parts[1]}"
        command = ["trajan", "github", "scan", "--repo", repo_path, "-o", "json", "--token", self.github_token]
        self.verbose(f"Scanning GitHub {repo_path} with Trajan")
        await self.execute_trajan(command, event)

    async def handle_gitlab(self, event, parsed, base_url, path_parts):
        if not self.gitlab_token:
            self.warning(f"Skipping {base_url} - GitLab token required for Trajan")
            return
        if len(path_parts) < 2:
            return
        repo_path = f"{path_parts[0]}/{path_parts[1]}"
        command = ["trajan", "gitlab", "scan", "--project", repo_path, "-o", "json", "--token", self.gitlab_token]
        self.verbose(f"Scanning GitLab {repo_path} with Trajan")
        await self.execute_trajan(command, event)

    async def handle_ado(self, event, parsed, base_url, path_parts):
        if not self.ado_token:
            self.warning(f"Skipping {base_url} - Azure DevOps token required for Trajan")
            return
        # e.g., https://dev.azure.com/org/project/_git/repo
        if len(path_parts) < 4 or path_parts[2] != "_git":
            return
        org = path_parts[0]
        project = path_parts[1]
        repo = path_parts[3]
        repo_path = f"{project}/{repo}"
        command = ["trajan", "ado", "scan", "--org", org, "--repo", repo_path, "-o", "json", "--token", self.ado_token]
        self.verbose(f"Scanning Azure DevOps {org}/{repo_path} with Trajan")
        await self.execute_trajan(command, event)

    async def handle_jfrog(self, event, parsed, base_url, path_parts):
        if not self.jfrog_token:
            self.warning(f"Skipping {base_url} - JFrog token required for Trajan")
            return
        command = [
            "trajan",
            "jfrog",
            "scan",
            "--url",
            base_url,
            "--secrets",
            "-o",
            "json",
            "--token",
            self.jfrog_token,
        ]
        self.verbose(f"Scanning JFrog {base_url} with Trajan")
        await self.execute_trajan(command, event, is_jfrog=True)

    async def handle_jenkins(self, event, parsed, base_url, path_parts):
        if not self.jenkins_token and not (self.jenkins_username and self.jenkins_password):
            self.warning(f"Skipping {base_url} - Jenkins token or username/password required for Trajan")
            return
        command = ["trajan", "jenkins", "scan", "--url", base_url, "-o", "json"]
        # Check if it's a specific job
        try:
            job_idx = path_parts.index("job")
            if job_idx + 1 < len(path_parts):
                command.extend(["--repo", path_parts[job_idx + 1]])
        except ValueError:
            pass
        if self.jenkins_token:
            command.extend(["--token", self.jenkins_token])
        if self.jenkins_username and self.jenkins_password:
            command.extend(["--username", self.jenkins_username, "--password", self.jenkins_password])
        self.verbose(f"Scanning Jenkins {base_url} with Trajan")
        await self.execute_trajan(command, event)

    async def execute_trajan(self, command, event, is_jfrog=False):
        process = await self.run_process(command)
        if not process or not process.stdout:
            return

        try:
            result = json.loads(process.stdout)
        except json.JSONDecodeError:
            self.debug(f"Trajan JSONDecodeError. Raw stdout: {process.stdout}")
            return

        if is_jfrog:
            await self.parse_jfrog_results(result, event)
        else:
            await self.parse_findings(result, event)

    async def parse_findings(self, result, event):
        for finding_data in result.get("findings", []):
            finding = {
                "name": f"Trajan - {finding_data.get('type', 'unknown')}",
                "description": finding_data.get("evidence", "No description provided."),
                "severity": finding_data.get("severity", "info").upper(),
                "confidence": "MEDIUM",
                "host": event.host,
            }
            workflow = finding_data.get("workflow", "")
            if workflow:
                finding["description"] += f" (Workflow: {workflow})"
            await self.emit_event(finding, "FINDING", event)

    async def parse_jfrog_results(self, result, event):
        for secret in result.get("artifactSecrets", []):
            finding = {
                "name": f"Trajan - JFrog Artifact Secret ({', '.join(secret.get('secretTypes', []))})",
                "description": f"Secret found in artifact {secret.get('artifact', 'unknown')} at path {secret.get('path', 'unknown')}",
                "severity": "HIGH",
                "confidence": "HIGH",
                "host": event.host,
            }
            await self.emit_event(finding, "FINDING", event)
        for secret in result.get("buildSecrets", []):
            finding = {
                "name": f"Trajan - JFrog Build Secret ({', '.join(secret.get('secretTypes', []))})",
                "description": f"Secret found in build {secret.get('buildName', 'unknown')} #{secret.get('buildNumber', '?')} env var {secret.get('envVar', 'unknown')}",
                "severity": "HIGH",
                "confidence": "HIGH",
                "host": event.host,
            }
            await self.emit_event(finding, "FINDING", event)
