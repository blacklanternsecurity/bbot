from pathlib import Path
from subprocess import CalledProcessError
from bbot.modules.templates.github import github


class git_clone(github):
    watched_events = ["CODE_REPOSITORY"]
    produced_events = ["FILESYSTEM"]
    flags = ["passive", "safe", "slow"]
    meta = {
        "description": "Clone code github repositories",
        "created_date": "2024-03-08",
        "author": "@domwhewell-sage",
    }
    options = {"api_key": "", "output_folder": ""}
    options_desc = {"api_key": "Github token", "output_folder": "Folder to clone repositories to"}

    deps_apt = ["git"]

    scope_distance_modifier = 2

    async def setup(self):
        output_folder = self.config.get("output_folder")
        if output_folder:
            self.output_dir = Path(output_folder) / "git_repos"
        else:
            self.output_dir = self.scan.home / "git_repos"
        self.helpers.mkdir(self.output_dir)
        return await super().setup()

    async def filter_event(self, event):
        if event.type == "CODE_REPOSITORY":
            if "git" not in event.tags:
                return False, "event is not a git repository"
        return True

    async def handle_event(self, event):
        repo_url = event.data.get("url")
        repo_path = await self.clone_git_repository(repo_url)
        if repo_path:
            self.verbose(f"Cloned {repo_url} to {repo_path}")
            codebase_event = self.make_event(
                {"path": str(repo_path)}, "FILESYSTEM", tags=["git", "folder"], source=event
            )
            codebase_event.scope_distance = event.scope_distance
            await self.emit_event(codebase_event)

    async def clone_git_repository(self, repository_url):
        if self.api_key:
            url = repository_url.replace("https://github.com", f"https://user:{self.api_key}@github.com")
        else:
            url = repository_url
        command = ["git", "-C", self.output_dir, "clone", url]
        try:
            output = await self.run_process(command, env={"GIT_TERMINAL_PROMPT": "0"}, check=True)
        except CalledProcessError as e:
            self.debug(f"Error cloning {url}. STDERR: {repr(e.stderr)}")
            return

        folder_name = output.stderr.split("Cloning into '")[1].split("'")[0]
        return self.output_dir / folder_name
