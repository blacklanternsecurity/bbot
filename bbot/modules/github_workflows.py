import zipfile
import fnmatch

from bbot.modules.templates.github import github


class github_workflows(github):
    watched_events = ["CODE_REPOSITORY"]
    produced_events = ["FILESYSTEM"]
    flags = ["passive", "safe", "code-enum"]
    meta = {
        "description": "Download a github repositories workflow logs and workflow artifacts",
        "created_date": "2024-04-29",
        "author": "@domwhewell-sage",
    }
    options = {"api_key": "", "num_logs": 1}
    options_desc = {
        "api_key": "Github token",
        "num_logs": "For each workflow fetch the last N successful runs logs (max 100)",
    }

    scope_distance_modifier = 2

    async def setup(self):
        self.num_logs = int(self.config.get("num_logs", 1))
        if self.num_logs > 100:
            self.log.error("num_logs option is capped at 100")
            return False
        self.output_dir = self.scan.home / "workflow_logs"
        self.helpers.mkdir(self.output_dir)
        return await super().setup()

    async def filter_event(self, event):
        if event.type == "CODE_REPOSITORY":
            if "git" not in event.tags and "github" not in event.data.get("url", ""):
                return False, "event is not a git repository"
        return True

    async def handle_event(self, event):
        repo_url = event.data.get("url")
        owner = repo_url.split("/")[-2]
        repo = repo_url.split("/")[-1]
        for workflow in await self.get_workflows(owner, repo):
            workflow_name = workflow.get("name")
            workflow_id = workflow.get("id")
            self.log.debug(f"Looking up runs for {workflow_name} in {owner}/{repo}")
            for run in await self.get_workflow_runs(owner, repo, workflow_id):
                run_id = run.get("id")
                workflow_url = f"https://github.com/{owner}/{repo}/actions/runs/{run_id}"
                self.log.debug(f"Downloading logs for {workflow_name}/{run_id} in {owner}/{repo}")
                for log in await self.download_run_logs(owner, repo, run_id):
                    logfile_event = self.make_event(
                        {
                            "path": str(log),
                            "description": f"Workflow run logs from {workflow_url}",
                        },
                        "FILESYSTEM",
                        tags=["textfile"],
                        parent=event,
                    )
                    await self.emit_event(
                        logfile_event,
                        context=f"{{module}} downloaded workflow run logs from {workflow_url} to {{event.type}}: {log}",
                    )
                artifacts = await self.get_run_artifacts(owner, repo, run_id)
                if artifacts:
                    for artifact in artifacts:
                        artifact_id = artifact.get("id")
                        artifact_name = artifact.get("name")
                        expired = artifact.get("expired")
                        if not expired:
                            filepath = await self.download_run_artifacts(owner, repo, artifact_id, artifact_name)
                            if filepath:
                                artifact_event = self.make_event(
                                    {
                                        "path": str(filepath),
                                        "description": f"Workflow run artifact from {workflow_url}",
                                    },
                                    "FILESYSTEM",
                                    tags=["zipfile"],
                                    parent=event,
                                )
                                await self.emit_event(
                                    artifact_event,
                                    context=f"{{module}} downloaded workflow run artifact from {workflow_url} to {{event.type}}: {filepath}",
                                )

    async def get_workflows(self, owner, repo):
        workflows = []
        url = f"{self.base_url}/repos/{owner}/{repo}/actions/workflows?per_page=100&page=" + "{page}"
        agen = self.api_page_iter(url, json=False)
        try:
            async for r in agen:
                if r is None:
                    break
                status_code = getattr(r, "status_code", 0)
                if status_code == 403:
                    self.warning("Github is rate-limiting us (HTTP status: 403)")
                    break
                if status_code != 200:
                    break
                try:
                    j = r.json().get("workflows", [])
                except Exception as e:
                    self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
                    break
                if not j:
                    break
                for item in j:
                    workflows.append(item)
        finally:
            agen.aclose()
        return workflows

    async def get_workflow_runs(self, owner, repo, workflow_id):
        runs = []
        url = f"{self.base_url}/repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs?status=success&per_page={self.num_logs}"
        r = await self.api_request(url)
        if r is None:
            return runs
        status_code = getattr(r, "status_code", 0)
        if status_code == 403:
            self.warning("Github is rate-limiting us (HTTP status: 403)")
            return runs
        if status_code != 200:
            return runs
        try:
            j = r.json().get("workflow_runs", [])
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return runs
        if not j:
            return runs
        for item in j:
            runs.append(item)
        return runs

    async def download_run_logs(self, owner, repo, run_id):
        folder = self.output_dir / owner / repo
        self.helpers.mkdir(folder)
        filename = f"run_{run_id}.zip"
        file_destination = folder / filename
        try:
            await self.helpers.download(
                f"{self.base_url}/repos/{owner}/{repo}/actions/runs/{run_id}/logs",
                filename=file_destination,
                headers=self.headers,
                raise_error=True,
                warn=False,
            )
            self.info(f"Downloaded logs for {owner}/{repo}/{run_id} to {file_destination}")
        except Exception as e:
            file_destination = None
            response = getattr(e, "response", None)
            status_code = getattr(response, "status_code", 0)
            if status_code == 403:
                self.warning(
                    f"The current access key does not have access to workflow {owner}/{repo}/{run_id} (status: {status_code})"
                )
            else:
                self.info(
                    f"The logs for {owner}/{repo}/{run_id} have expired and are no longer available (status: {status_code})"
                )
        # Secrets are duplicated in the individual workflow steps so just extract the main log files from the top folder
        if file_destination:
            main_logs = []
            with zipfile.ZipFile(file_destination, "r") as logzip:
                for name in logzip.namelist():
                    if fnmatch.fnmatch(name, "*.txt") and not "/" in name:
                        logzip.extract(name, folder)
                        main_logs.append(folder / name)
            return main_logs
        else:
            return []

    async def get_run_artifacts(self, owner, repo, run_id):
        artifacts = []
        url = f"{self.base_url}/repos/{owner}/{repo}/actions/runs/{run_id}/artifacts"
        r = await self.api_request(url)
        if r is None:
            return artifacts
        status_code = getattr(r, "status_code", 0)
        if status_code == 403:
            self.warning("Github is rate-limiting us (HTTP status: 403)")
            return artifacts
        if status_code != 200:
            return artifacts
        try:
            j = r.json().get("artifacts", [])
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return artifacts
        if not j:
            return artifacts
        for item in j:
            artifacts.append(item)
        return artifacts

    async def download_run_artifacts(self, owner, repo, artifact_id, artifact_name):
        folder = self.output_dir / owner / repo
        self.helpers.mkdir(folder)
        file_destination = folder / artifact_name
        try:
            await self.helpers.download(
                f"{self.base_url}/repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip",
                filename=file_destination,
                headers=self.headers,
                raise_error=True,
                warn=False,
            )
            self.info(
                f"Downloaded workflow artifact {owner}/{repo}/{artifact_id}/{artifact_name} to {file_destination}"
            )
        except Exception as e:
            file_destination = None
            response = getattr(e, "response", None)
            status_code = getattr(response, "status_code", 0)
            if status_code == 403:
                self.warning(
                    f"The current access key does not have access to workflow artifacts {owner}/{repo}/{artifact_id} (status: {status_code})"
                )
        return file_destination
