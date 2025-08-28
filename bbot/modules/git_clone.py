from pathlib import Path
from subprocess import CalledProcessError
from bbot.modules.templates.github import github


class git_clone(github):
    watched_events = ["CODE_REPOSITORY"]
    produced_events = ["FILESYSTEM"]
    flags = ["passive", "safe", "slow", "code-enum"]
    meta = {
        "description": "Clone code github repositories",
        "created_date": "2024-03-08",
        "author": "@domwhewell-sage",
    }
    options = {"api_key": "", "output_folder": ""}
    options_desc = {
        "api_key": "Github token",
        "output_folder": "Folder to clone repositories to. If not specified, cloned repositories will be deleted when the scan completes, to minimize disk usage.",
    }

    deps_apt = ["git"]

    scope_distance_modifier = 2

    async def setup(self):
        output_folder = self.config.get("output_folder")
        self.output_dir = Path(output_folder) / "git_repos" if output_folder else self.scan.temp_dir / "git_repos"
        self.helpers.mkdir(self.output_dir)
        return await super().setup()

    async def filter_event(self, event):
        if event.type == "CODE_REPOSITORY" and "git" not in event.tags:
            return False, "event is not a git repository"
        return True

    async def handle_event(self, event):
        repository_url = event.data.get("url")
        repository_path = await self.clone_git_repository(repository_url)
        if repository_path:
            self.verbose(f"Cloned {repository_url} to {repository_path}")
            codebase_event = self.make_event({"path": str(repository_path)}, "FILESYSTEM", tags=["git"], parent=event)
            await self.emit_event(
                codebase_event,
                context=f"{{module}} cloned git repository at {repository_url} to {{event.type}}: {repository_path}",
            )

    async def clone_git_repository(self, repository_url):
        owner = repository_url.split("/")[-2]
        folder = self.output_dir / owner
        self.helpers.mkdir(folder)

        command = ["git", "-C", folder, "clone", repository_url]
        env = {"GIT_TERMINAL_PROMPT": "0"}

        try:
            hostname = self.helpers.urlparse(repository_url).hostname
            if hostname and self.api_key:
                _, domain = self.helpers.split_domain(hostname)
                # only use the api key if the domain is github.com
                if domain == "github.com":
                    env["GIT_HELPER"] = (
                        f'!f() {{ case "$1" in get) '
                        f"echo username=x-access-token; "
                        f"echo password={self.api_key};; "
                        f'esac; }}; f "$@"'
                    )
                    command = (
                        command[:1]
                        + [
                            "-c",
                            "credential.helper=",
                            "-c",
                            "credential.useHttpPath=true",
                            "--config-env=credential.helper=GIT_HELPER",
                        ]
                        + command[1:]
                    )

            output = await self.run_process(command, env=env, check=True)
        except CalledProcessError as e:
            self.debug(f"Error cloning {repository_url}. STDERR: {repr(e.stderr)}")
            return

        folder_name = output.stderr.split("Cloning into '")[1].split("'")[0]
        return folder / folder_name
