from bbot.modules.templates.github import github


class github_workflows(github):
    watched_events = ["CODE_REPOSITORY"]
    produced_events = ["HTTP_RESPONSE"]
    flags = ["passive", "safe"]
    meta = {"description": "Query Github's API for the repositories workflow logs"}
    options = {"api_key": ""}
    options_desc = {
        "api_key": "Github token",
    }

    # scope_distance_modifier = 2

    async def setup(self):
        return await super().setup()

    async def filter_event(self, event):
        if event.type == "CODE_REPOSITORY":
            if "git" not in event.tags:
                return False, "event is not a git repository"
        return True

    async def handle_event(self, event):
        # repo_url = event.data.get("url")
        owner = "blacklanternsecurity"
        repo = "bbot"
        for workflow in await self.get_workflows(owner, repo):
            workflow_name = workflow.get("name")
            workflow_id = workflow.get("id")
            self.log.debug(f"Looking up runs for {workflow_name} in {owner}/{repo}")
            for run in await self.get_workflow_runs(owner, repo, workflow_id):
                run_id = run.get("id")
                self.log.debug(f"Looking up jobs for {workflow_name}/{run_id} in {owner}/{repo}")
                for job in await self.get_run_jobs(owner, repo, run_id):
                    job_id = job.get("id")
                    commit_id = job.get("head_sha")
                    steps = job.get("steps", [])
                    for step in steps:
                        if step.get("conclusion") == "success":
                            step_name = step.get("name")
                            number = step.get("number")
                            self.log.debug(
                                f"Requesting {workflow_name}/run {run_id}/job {job_id}/{step_name} log for {owner}/{repo}"
                            )
                            # Request log step from the html_url as that bypasses the admin restrictions from using the API
                            response = await self.helpers.request(
                                f"https://github.com/{owner}/{repo}/commit/{commit_id}/checks/{job_id}/logs/{number}",
                                follow_redirects=True,
                            )
                            if response:
                                blob_url = response.headers.get("Location", "")
                                if blob_url:
                                    url_event = self.make_event(
                                        blob_url, "URL_UNVERIFIED", source=event, tags=["httpx-safe"]
                                    )
                                    if not url_event:
                                        continue
                                    url_event.scope_distance = event.scope_distance
                                    await self.emit_event(url_event)

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
                    j = r.json()
                except Exception as e:
                    self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
                    break
                if not j:
                    break
                for item in j.get("workflows", []):
                    workflows.append(item)
        finally:
            agen.aclose()
        return workflows

    async def get_workflow_runs(self, owner, repo, workflow_id):
        runs = []
        url = (
            f"{self.base_url}/repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs?per_page=100&page=" + "{page}"
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
                    j = r.json()
                except Exception as e:
                    self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
                    break
                if not j:
                    break
                for item in j.get("workflow_runs", []):
                    runs.append(item)
        finally:
            agen.aclose()
        return runs

    async def get_run_jobs(self, owner, repo, run_id):
        jobs = []
        url = f"{self.base_url}/repos/{owner}/{repo}/actions/runs/{run_id}/jobs?per_page=100&page=" + "{page}"
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
                    j = r.json()
                except Exception as e:
                    self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
                    break
                if not j:
                    break
                for item in j.get("jobs", []):
                    jobs.append(item)
        finally:
            agen.aclose()
        return jobs
