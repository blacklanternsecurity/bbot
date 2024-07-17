import zipfile
import fnmatch

from bbot.modules.templates.github import github


class github_workflows(github):
    watched_events = ["CODE_REPOSITORY"]
    produced_events = ["FILESYSTEM"]
    flags = ["passive", "safe"]
    meta = {
        "description": "Download a github repositories workflow logs",
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
                self.log.debug(f"Downloading logs for {workflow_name}/{run_id} in {owner}/{repo}")
                for log in await self.download_run_logs(owner, repo, run_id):
                    logfile_event = self.make_event(
                        {
                            "path": str(log),
                            "description": f"Workflow run logs from https://github.com/{owner}/{repo}/actions/runs/{run_id}",
                        },
                        "FILESYSTEM",
                        tags=["textfile"],
                        source=event,
                    )
                    logfile_event.scope_distance = event.scope_distance
                    await self.emit_event(logfile_event)

    async def get_workflows(self, owner, repo):
        workflows = []
        url = f"{self.base_url}/repos/{owner}/{repo}/actions/workflows?per_page=100&page=" + "{page}"
        agen = self.helpers.api_page_iter(url, headers=self.headers, json=False)
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
        r = await self.helpers.request(url, headers=self.headers)
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
