import json
from subprocess import CompletedProcess

from .base import ModuleTestBase


trajan_github_output = json.dumps(
    {
        "summary": {"repositories": 1, "workflows": 3, "findings": 1, "errors": 0},
        "findings": [
            {
                "type": "pwn_request",
                "severity": "critical",
                "confidence": "high",
                "complexity": "zero_click",
                "platform": "github",
                "class": "injection",
                "repository": "blacklanternsecurity/bbot",
                "workflow": "CI",
                "workflow_file": ".github/workflows/ci.yml",
                "job": "build",
                "step": "checkout",
                "line": 42,
                "trigger": "pull_request_target",
                "evidence": "on: pull_request_target\nwith:\n  ref: ${{ github.event.pull_request.head.sha }}",
                "remediation": "Avoid using pull_request_target with user-controlled refs",
            }
        ],
    }
)

trajan_gitlab_output = json.dumps(
    {
        "summary": {"repositories": 1, "workflows": 2, "findings": 1, "errors": 0},
        "findings": [
            {
                "type": "token_exposure",
                "severity": "high",
                "confidence": "high",
                "platform": "gitlab",
                "class": "secrets_exposure",
                "repository": "someorg/somerepo",
                "workflow": "deploy",
                "workflow_file": ".gitlab-ci.yml",
                "evidence": "CI_JOB_TOKEN exposed in script block via echo $CI_JOB_TOKEN",
            }
        ],
    }
)

trajan_ado_output = json.dumps(
    {
        "summary": {"repositories": 1, "workflows": 1, "findings": 1, "errors": 0},
        "findings": [
            {
                "type": "script_injection",
                "severity": "high",
                "confidence": "medium",
                "platform": "azuredevops",
                "class": "injection",
                "repository": "myproject/myrepo",
                "workflow": "Build Pipeline",
                "workflow_file": "azure-pipelines.yml",
                "job": "build",
                "step": "run_script",
                "line": 15,
                "trigger": "pullRequest",
                "evidence": "script: echo $(Build.SourceBranch)",
            }
        ],
    }
)

trajan_jfrog_output = json.dumps(
    {
        "instance": "https://mycompany.jfrog.io",
        "artifactSecrets": [
            {
                "artifact": "config.yaml",
                "path": "libs-release/com/example/config.yaml",
                "repo": "libs-release",
                "secretTypes": ["aws_access_key", "generic_api_key"],
                "value": "AKIA...",
            }
        ],
        "buildSecrets": [
            {
                "buildName": "release-pipeline",
                "buildNumber": "42",
                "envVar": "AWS_SECRET_KEY",
                "value": "wJalr...",
                "secretTypes": ["aws_secret_key"],
            }
        ],
        "remoteRepoCredentials": [],
        "totalSecrets": 2,
    }
)

trajan_jenkins_output = json.dumps(
    {
        "summary": {"repositories": 1, "workflows": 4, "findings": 1, "errors": 0},
        "findings": [
            {
                "type": "jenkins_script_console",
                "severity": "critical",
                "confidence": "high",
                "platform": "jenkins",
                "class": "configuration",
                "repository": "deploy-pipeline",
                "workflow": "deploy-pipeline",
                "evidence": "Script console accessible at /script without authentication",
            }
        ],
    }
)


class TestTrajanGithub(ModuleTestBase):
    targets = ["https://github.com/blacklanternsecurity/bbot"]
    modules_overrides = ["trajan"]
    config_overrides = {"modules": {"trajan": {"github_token": "test-gh-token"}}}

    async def setup_after_prep(self, module_test):
        async def mock_run(*command, **kwargs):
            cmd = command[0] if len(command) == 1 and isinstance(command[0], list) else list(command)
            if "trajan" in cmd:
                assert "github" in cmd
                assert "--repo" in cmd
                repo_idx = cmd.index("--repo")
                assert cmd[repo_idx + 1] == "blacklanternsecurity/bbot"
                assert "--token" in cmd
                token_idx = cmd.index("--token")
                assert cmd[token_idx + 1] == "test-gh-token"
                return CompletedProcess(cmd, 0, trajan_github_output, "")
            return CompletedProcess(cmd, 1, "", "")

        module_test.monkeypatch.setattr(module_test.scan.helpers, "run", mock_run)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert len(findings) == 1, f"Expected 1 FINDING, got {len(findings)}"
        finding = findings[0]
        assert "pwn_request" in finding.data["name"]
        assert finding.data["severity"] == "CRITICAL"
        assert "CI" in finding.data["description"]


class TestTrajanGitlab(ModuleTestBase):
    targets = ["https://gitlab.com/someorg/somerepo"]
    modules_overrides = ["trajan"]
    config_overrides = {"modules": {"trajan": {"gitlab_token": "test-gl-token"}}}

    async def setup_after_prep(self, module_test):
        async def mock_run(*command, **kwargs):
            cmd = command[0] if len(command) == 1 and isinstance(command[0], list) else list(command)
            if "trajan" in cmd:
                assert "gitlab" in cmd
                assert "--project" in cmd
                project_idx = cmd.index("--project")
                assert cmd[project_idx + 1] == "someorg/somerepo"
                assert "--token" in cmd
                token_idx = cmd.index("--token")
                assert cmd[token_idx + 1] == "test-gl-token"
                return CompletedProcess(cmd, 0, trajan_gitlab_output, "")
            return CompletedProcess(cmd, 1, "", "")

        module_test.monkeypatch.setattr(module_test.scan.helpers, "run", mock_run)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert len(findings) == 1, f"Expected 1 FINDING, got {len(findings)}"
        finding = findings[0]
        assert "token_exposure" in finding.data["name"]
        assert finding.data["severity"] == "HIGH"
        assert "deploy" in finding.data["description"]


class TestTrajanAdo(ModuleTestBase):
    targets = ["https://dev.azure.com/myorg/myproject/_git/myrepo"]
    modules_overrides = ["trajan"]
    config_overrides = {"modules": {"trajan": {"ado_token": "test-ado-token"}}}

    async def setup_after_prep(self, module_test):
        async def mock_run(*command, **kwargs):
            cmd = command[0] if len(command) == 1 and isinstance(command[0], list) else list(command)
            if "trajan" in cmd:
                assert "ado" in cmd
                assert "--org" in cmd
                org_idx = cmd.index("--org")
                assert cmd[org_idx + 1] == "myorg"
                assert "--repo" in cmd
                repo_idx = cmd.index("--repo")
                assert cmd[repo_idx + 1] == "myproject/myrepo"
                assert "--token" in cmd
                token_idx = cmd.index("--token")
                assert cmd[token_idx + 1] == "test-ado-token"
                return CompletedProcess(cmd, 0, trajan_ado_output, "")
            return CompletedProcess(cmd, 1, "", "")

        module_test.monkeypatch.setattr(module_test.scan.helpers, "run", mock_run)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert len(findings) == 1, f"Expected 1 FINDING, got {len(findings)}"
        finding = findings[0]
        assert "script_injection" in finding.data["name"]
        assert finding.data["severity"] == "HIGH"
        assert "Build Pipeline" in finding.data["description"]


class TestTrajanJfrog(ModuleTestBase):
    targets = ["https://mycompany.jfrog.io/artifactory/libs-release"]
    modules_overrides = ["trajan"]
    config_overrides = {"modules": {"trajan": {"jfrog_token": "test-jfrog-token"}}}

    async def setup_after_prep(self, module_test):
        async def mock_run(*command, **kwargs):
            cmd = command[0] if len(command) == 1 and isinstance(command[0], list) else list(command)
            if "trajan" in cmd:
                assert "jfrog" in cmd
                assert "--url" in cmd
                url_idx = cmd.index("--url")
                assert cmd[url_idx + 1] == "https://mycompany.jfrog.io"
                assert "--secrets" in cmd
                assert "--token" in cmd
                token_idx = cmd.index("--token")
                assert cmd[token_idx + 1] == "test-jfrog-token"
                return CompletedProcess(cmd, 0, trajan_jfrog_output, "")
            return CompletedProcess(cmd, 1, "", "")

        module_test.monkeypatch.setattr(module_test.scan.helpers, "run", mock_run)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert len(findings) == 2, f"Expected 2 FINDINGs (1 artifact + 1 build secret), got {len(findings)}"
        artifact_findings = [e for e in findings if "Artifact Secret" in e.data["name"]]
        assert len(artifact_findings) == 1
        assert "aws_access_key" in artifact_findings[0].data["name"]
        assert "config.yaml" in artifact_findings[0].data["description"]
        build_findings = [e for e in findings if "Build Secret" in e.data["name"]]
        assert len(build_findings) == 1
        assert "aws_secret_key" in build_findings[0].data["name"]
        assert "release-pipeline" in build_findings[0].data["description"]


class TestTrajanJenkins(ModuleTestBase):
    """Test Jenkins detection via TECHNOLOGY event on a non-jenkins hostname."""

    targets = ["blacklanternsecurity.com"]
    modules_overrides = ["trajan"]
    config_overrides = {"modules": {"trajan": {"jenkins_token": "test-jenkins-token"}}}

    async def setup_after_prep(self, module_test):
        # Inject a TECHNOLOGY event as if gowitness/shodan detected Jenkins
        tech_event = module_test.scan.make_event(
            {
                "technology": "jenkins",
                "url": "https://ci.blacklanternsecurity.com:8080/job/deploy-pipeline",
                "host": "ci.blacklanternsecurity.com",
            },
            "TECHNOLOGY",
            parent=module_test.scan.root_event,
        )
        await module_test.scan.ingress_module.queue_event(tech_event, {})

        async def mock_run(*command, **kwargs):
            cmd = command[0] if len(command) == 1 and isinstance(command[0], list) else list(command)
            if "trajan" in cmd:
                assert "jenkins" in cmd
                assert "--url" in cmd
                url_idx = cmd.index("--url")
                assert cmd[url_idx + 1] == "https://ci.blacklanternsecurity.com:8080"
                assert "--repo" in cmd
                repo_idx = cmd.index("--repo")
                assert cmd[repo_idx + 1] == "deploy-pipeline"
                assert "--token" in cmd
                token_idx = cmd.index("--token")
                assert cmd[token_idx + 1] == "test-jenkins-token"
                return CompletedProcess(cmd, 0, trajan_jenkins_output, "")
            return CompletedProcess(cmd, 1, "", "")

        module_test.monkeypatch.setattr(module_test.scan.helpers, "run", mock_run)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert len(findings) == 1, f"Expected 1 FINDING, got {len(findings)}"
        finding = findings[0]
        assert "jenkins_script_console" in finding.data["name"]
        assert finding.data["severity"] == "CRITICAL"


class TestTrajanJfrogTechnology(ModuleTestBase):
    """Test JFrog/Artifactory detection via TECHNOLOGY event on a non-jfrog hostname."""

    targets = ["blacklanternsecurity.com"]
    modules_overrides = ["trajan"]
    config_overrides = {"modules": {"trajan": {"jfrog_token": "test-jfrog-token"}}}

    async def setup_after_prep(self, module_test):
        # Inject an "artifactory" TECHNOLOGY event on a self-hosted instance
        tech_event = module_test.scan.make_event(
            {
                "technology": "artifactory",
                "url": "https://artifacts.blacklanternsecurity.com/",
                "host": "artifacts.blacklanternsecurity.com",
            },
            "TECHNOLOGY",
            parent=module_test.scan.root_event,
        )
        await module_test.scan.ingress_module.queue_event(tech_event, {})

        async def mock_run(*command, **kwargs):
            cmd = command[0] if len(command) == 1 and isinstance(command[0], list) else list(command)
            if "trajan" in cmd:
                assert "jfrog" in cmd
                assert "--url" in cmd
                url_idx = cmd.index("--url")
                assert cmd[url_idx + 1] == "https://artifacts.blacklanternsecurity.com"
                assert "--secrets" in cmd
                assert "--token" in cmd
                token_idx = cmd.index("--token")
                assert cmd[token_idx + 1] == "test-jfrog-token"
                return CompletedProcess(cmd, 0, trajan_jfrog_output, "")
            return CompletedProcess(cmd, 1, "", "")

        module_test.monkeypatch.setattr(module_test.scan.helpers, "run", mock_run)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert len(findings) == 2, f"Expected 2 FINDINGs (1 artifact + 1 build secret), got {len(findings)}"
        artifact_findings = [e for e in findings if "Artifact Secret" in e.data["name"]]
        assert len(artifact_findings) == 1
        build_findings = [e for e in findings if "Build Secret" in e.data["name"]]
        assert len(build_findings) == 1
