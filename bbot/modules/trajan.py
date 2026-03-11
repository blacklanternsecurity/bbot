import json
import re
from bbot.modules.base import BaseModule

class trajan(BaseModule):
    watched_events = ["CODE_REPOSITORY", "URL_UNVERIFIED"]
    produced_events = ["FINDING"]
    flags = ["passive", "safe", "code-enum"]
    meta = {
        "description": "Scans GitHub, GitLab, Azure DevOps, Jenkins, and JFrog for misconfigurations using Trajan",
        "author": "N7WERA (Credit to Praetorian for trajan)",
    }

    # Configuration options
    options = {
        "version": "1.0.0",
        "github_token": "",
        "gitlab_token": "",
        "ado_token": "",
        "jfrog_token": "",
        "jenkins_username": "",
        "jenkins_password": "",
        "jenkins_token": "",
    }
    options_desc = {
        "version": "Trajan version to download and use",
        "github_token": "GitHub API token for rate-limiting and private repo access",
        "gitlab_token": "GitLab API token for private repo access",
        "ado_token": "Azure DevOps Personal Access Token (PAT)",
        "jfrog_token": "JFrog API token",
        "jenkins_username": "Jenkins username for basic auth",
        "jenkins_password": "Jenkins password for basic auth",
        "jenkins_token": "Jenkins API token",
    }

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
        return True

    async def handle_event(self, event):
        repo_url = ""
        if event.type == "CODE_REPOSITORY":
            repo_url = event.data.get("url", "")
        elif event.type == "URL_UNVERIFIED":
            repo_url = str(event.data)

        if not repo_url:
            return

        command = None

        # GitHub
        if "github.com" in repo_url:
            if not self.github_token:
                self.warning(f"Skipping {repo_url} - GitHub token required for Trajan")
                return
            match = re.search(r"github\.com/([^/]+)/([^/?#]+)", repo_url)
            if match:
                repo_path = f"{match.group(1)}/{match.group(2)}"
                command = ["trajan", "github", "scan", "--repo", repo_path, "-o", "json"]
                if self.github_token:
                    command.extend(["--token", self.github_token])
                self.verbose(f"Scanning GitHub {repo_path} with Trajan")

        # GitLab
        elif "gitlab.com" in repo_url:
            if not self.gitlab_token:
                self.warning(f"Skipping {repo_url} - GitLab token required for Trajan")
                return
            match = re.search(r"gitlab\.com/([^/]+)/([^/?#]+)", repo_url)
            if match:
                repo_path = f"{match.group(1)}/{match.group(2)}"
                command = ["trajan", "gitlab", "scan", "--project", repo_path, "-o", "json"]
                if self.gitlab_token:
                    command.extend(["--token", self.gitlab_token])
                self.verbose(f"Scanning GitLab {repo_path} with Trajan")

        # Azure DevOps
        elif "dev.azure.com" in repo_url:
            if not self.ado_token:
                self.warning(f"Skipping {repo_url} - Azure DevOps token required for Trajan")
                return
            # e.g., https://dev.azure.com/org/project/_git/repo
            match = re.search(r"dev\.azure\.com/([^/]+)/([^/]+)/_git/([^/?#]+)", repo_url)
            if match:
                org = match.group(1)
                project = match.group(2)
                repo = match.group(3)
                repo_path = f"{project}/{repo}"
                command = ["trajan", "ado", "scan", "--org", org, "--repo", repo_path, "-o", "json"]
                if self.ado_token:
                    command.extend(["--token", self.ado_token])
                self.verbose(f"Scanning Azure DevOps {org}/{repo_path} with Trajan")

        # JFrog
        elif "jfrog.io" in repo_url or "artifactory" in repo_url:
            if not self.jfrog_token:
                self.warning(f"Skipping {repo_url} - JFrog token required for Trajan")
                return
            match = re.search(r"(https?://[^/]+)", repo_url)
            if match:
                base_url = match.group(1)
                command = ["trajan", "jfrog", "scan", "--url", base_url, "--secrets", "-o", "json"]
                if self.jfrog_token:
                    command.extend(["--token", self.jfrog_token])
                self.verbose(f"Scanning JFrog {base_url} with Trajan")

        # Jenkins
        elif "jenkins" in repo_url:
            if not self.jenkins_token and not (self.jenkins_username and self.jenkins_password):
                self.warning(f"Skipping {repo_url} - Jenkins token or username/password required for Trajan")
                return
            match = re.search(r"(https?://[^/]+)", repo_url)
            if match:
                base_url = match.group(1)
                command = ["trajan", "jenkins", "scan", "--url", base_url, "-o", "json"]
                
                # Check if it's a specific job
                job_match = re.search(r"/job/([^/]+)", repo_url)
                if job_match:
                    command.extend(["--repo", job_match.group(1)])

                if self.jenkins_token:
                    command.extend(["--token", self.jenkins_token])
                if self.jenkins_username and self.jenkins_password:
                    command.extend(["--username", self.jenkins_username, "--password", self.jenkins_password])

                self.verbose(f"Scanning Jenkins {repo_url} with Trajan")

        if not command:
            return

        # Execute and parse findings
        process = await self.helpers.run(command)
        if not process or not process.stdout:
            return

        try:
            result = json.loads(process.stdout)
            
            findings = result.get("findings", [])
            for finding_data in findings:
                # Map Trajan's JSON output to BBOT's FINDING format
                finding = {
                    "name": f"Trajan - {finding_data.get('type', finding_data.get('title', 'Misconfiguration'))}",
                    "description": finding_data.get("evidence", "No description provided."),
                    "severity": finding_data.get("severity", "INFO").upper(),
                    "confidence": "MODERATE",
                    "host": event.host
                }

                # Append extra details to description if available
                workflow = finding_data.get("workflow", "")
                if workflow:
                    finding["description"] += f" (Workflow: {workflow})"

                await self.emit_event(finding, "FINDING", event)

        except json.JSONDecodeError:
            # Log any non-JSON output (like progress bars or errors) to debug
            self.debug(f"Trajan JSONDecodeError. Raw stdout: {process.stdout}")
