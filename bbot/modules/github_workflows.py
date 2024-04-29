from datetime import date, timedelta

from bbot.modules.templates.github import github


class github_workflows(github):
    watched_events = ["CODE_REPOSITORY"]
    produced_events = ["FILESYSTEM"]
    flags = ["passive", "safe"]
    meta = {"description": "Download a github repositories workflow logs"}
    options = {"api_key": "", "historical_logs": 7}
    options_desc = {
        "api_key": "Github token",
        "historical_logs": "Fetch logs that are at most this many days old (default: 7)",
    }

    scope_distance_modifier = 2

    async def setup(self):
        self.historical_logs = int(self.options.get("historical_logs", 7))
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
                log_path = await self.download_run_logs(owner, repo, run_id)
                if log_path:
                    self.verbose(f"Downloaded repository workflow logs to {log_path}")
                    logfile_event = self.make_event(
                        {"path": str(log_path)}, "FILESYSTEM", tags=["zipfile"], source=event
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
        created_date = date.today() - timedelta(days=self.historical_logs)
        formated_date = created_date.strftime("%Y-%m-%d")
        url = (
            f"{self.base_url}/repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs?created=>{formated_date}&per_page=100&page="
            + "{page}"
        )
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
                    j = r.json().get("workflow_runs", [])
                except Exception as e:
                    self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
                    break
                if not j:
                    break
                for item in j:
                    runs.append(item)
        finally:
            agen.aclose()
        return runs

    async def download_run_logs(self, owner, repo, run_id):
        file_destination = self.output_dir / f"{owner}_{repo}_run_{run_id}.zip"
        result = await self.helpers.download(
            f"{self.base_url}/repos/{owner}/{repo}/actions/runs/{run_id}/logs", filename=file_destination
        )
        if result:
            self.info(f"Downloaded logs for {owner}/{repo}/{run_id} to {file_destination}")
            return file_destination
        else:
            self.warning(f"Failed to download logs for {owner}/{repo}/{run_id}")
            return None
