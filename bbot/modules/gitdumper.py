import asyncio
from pathlib import Path
from subprocess import CalledProcessError
from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class gitdumper(BaseModule):
    watched_events = ["CODE_REPOSITORY"]
    produced_events = ["FILESYSTEM"]
    flags = ["safe", "passive", "slow", "code-enum", "download"]
    meta = {
        "description": "Download a leaked .git folder recursively or by fuzzing common names",
        "created_date": "2025-02-11",
        "author": "@domwhewell-sage",
    }

    class Config(BaseModuleConfig):
        output_folder: str = Field(
            "",
            description="Folder to download repositories to. If not specified, downloaded repositories will be deleted when the scan completes, to minimize disk usage.",
        )
        fuzz_tags: bool = Field(
            False, description="Fuzz for common git tag names (v0.0.1, 0.0.2, etc.) up to the max_semanic_version"
        )
        max_semanic_version: int = Field(10, description="Maximum version number to fuzz for (default < v10.10.10)")

    scope_distance_modifier = 2

    async def setup(self):
        self.urls_downloaded = set()
        output_folder = self.config.get("output_folder", "")
        if output_folder:
            self.output_dir = Path(output_folder) / "git_repos"
        else:
            self.output_dir = self.scan.temp_dir / "git_repos"
        self.helpers.mkdir(self.output_dir)
        self.ref_regex = self.helpers.re.compile(r"ref: refs/heads/([a-zA-Z\d_-]+)")
        self.obj_regex = self.helpers.re.compile(r"[a-f0-9]{40}")
        self.pack_regex = self.helpers.re.compile(r"pack-([a-f0-9]{40})\.pack")
        self.git_files = [
            "HEAD",
            "description",
            "config",
            "COMMIT_EDITMSG",
            "index",
            "packed-refs",
            "info/refs",
            "info/exclude",
            "refs/stash",
            "refs/wip/index/refs/heads/master",
            "refs/wip/wtree/refs/heads/master",
            "logs/HEAD",
            "objects/info/packs",
        ]
        self.info("Compiling fuzz list with common branch names")
        branch_names = [
            "bugfix",
            "daily",
            "dev",
            "develop",
            "development",
            "feat",
            "feature",
            "fix",
            "hotfix",
            "integration",
            "issue",
            "main",
            "master",
            "ng",
            "prod",
            "production",
            "qa",
            "quickfix",
            "release",
            "stable",
            "stage",
            "staging",
            "test",
            "testing",
            "trunk",
            "wip",
        ]
        url_patterns = [
            "logs/refs/heads/{branch}",
            "logs/refs/remotes/origin/{branch}",
            "refs/remotes/origin/{branch}",
            "refs/heads/{branch}",
        ]
        for branch in branch_names:
            for pattern in url_patterns:
                self.git_files.append(pattern.format(branch=branch))
        self.fuzz_tags = self.config.get("fuzz_tags", "10")
        self.max_semanic_version = self.config.get("max_semanic_version", "10")
        if self.fuzz_tags:
            self.info("Adding symantec version tags to fuzz list")
            for major in range(self.max_semanic_version):
                for minor in range(self.max_semanic_version):
                    for patch in range(self.max_semanic_version):
                        self.verbose(f"{major}.{minor}.{patch}")
                        self.git_files.append(f"refs/tags/{major}.{minor}.{patch}")
                        self.verbose(f"v{major}.{minor}.{patch}")
                        self.git_files.append(f"refs/tags/v{major}.{minor}.{patch}")
        else:
            self.info("Adding symantec version tags to fuzz list (v0.0.1, 0.0.1, v1.0.0, 1.0.0)")
            for path in ["refs/tags/v0.0.1", "refs/tags/0.0.1", "refs/tags/v1.0.0", "refs/tags/1.0.0"]:
                self.git_files.append(path)
        return await super().setup()

    async def filter_event(self, event):
        if event.type == "CODE_REPOSITORY":
            if "git-directory" not in event.tags:
                return False, "event is not a leaked .git directory"
        return True

    async def handle_event(self, event):
        repo_url = event.url
        self.info(f"Processing leaked .git directory at {repo_url}")
        repo_folder = self.output_dir / self.helpers.tagify(repo_url)
        self.helpers.mkdir(repo_folder)
        dir_listing = await self.directory_listing_enabled(repo_url)
        if dir_listing:
            urls = await self.recursive_dir_list(dir_listing)
            try:
                result = await self.download_files(urls, repo_folder)
            except asyncio.CancelledError:
                self.verbose(f"Cancellation requested while downloading files from {repo_url}")
                result = True
        else:
            result = await self.git_fuzz(repo_url, repo_folder)
        if result:
            await self.git_checkout(repo_folder)
            codebase_event = self.make_event({"path": str(repo_folder)}, "FILESYSTEM", tags=["git"], parent=event)
            await self.emit_event(
                codebase_event,
                context=f"{{module}} cloned git repo at {repo_url} to {{event.type}}: {str(repo_folder)}",
            )
        else:
            self.helpers.rm_rf(repo_folder)

    async def directory_listing_enabled(self, repo_url):
        response = await self.helpers.request(repo_url)
        if "<title>Index of" in getattr(response, "text", ""):
            self.info(f"Directory listing enabled at {repo_url}")
            return response
        return None

    async def recursive_dir_list(self, dir_listing):
        file_list = []
        soup = self.helpers.beautifulsoup(dir_listing.text, "html.parser")
        links = soup.find_all("a")
        for link in links:
            href = link["href"]
            if href == "../" or href == "/":
                continue
            if href.endswith("/"):
                folder_url = self.helpers.urljoin(str(dir_listing.url), href)
                response = await self.helpers.request(folder_url)
                if getattr(response, "status_code", 0) == 200:
                    file_list.extend(await self.recursive_dir_list(response))
            else:
                file_url = self.helpers.urljoin(str(dir_listing.url), href)
                # Ensure the file is in the same domain as the directory listing
                if file_url.startswith(str(dir_listing.url)):
                    url = self.helpers.urlparse(file_url)
                    file_list.append(url)
        return file_list

    async def git_fuzz(self, repo_url, repo_folder):
        self.info("Directory listing not enabled, fuzzing common git files")
        url_list = []
        for file in self.git_files:
            url_list.append(self.helpers.urlparse(self.helpers.urljoin(repo_url, file)))
        result = await self.download_files(url_list, repo_folder)
        if result:
            await self.download_current_branch(repo_url, repo_folder)
            try:
                await self.download_git_objects(repo_url, repo_folder)
            except asyncio.CancelledError:
                self.verbose(f"Cancellation requested while downloading git objects from {repo_url}")
            await self.download_git_packs(repo_url, repo_folder)
            return True
        else:
            return False

    async def download_current_branch(self, repo_url, repo_folder):
        for branch in await self.regex_files(self.ref_regex, file=repo_folder / ".git/HEAD"):
            await self.download_files(
                [self.helpers.urlparse(self.helpers.urljoin(repo_url, f"refs/heads/{branch}"))], repo_folder
            )

    async def download_git_objects(self, url, folder):
        for object in await self.regex_files(self.obj_regex, folder=folder):
            await self.download_object(object, url, folder)

    async def download_git_packs(self, url, folder):
        url_list = []
        for sha1 in await self.regex_files(self.pack_regex, file=folder / ".git/objects/info/packs"):
            url_list.append(self.helpers.urlparse(self.helpers.urljoin(url, f"objects/pack/pack-{sha1}.idx")))
            url_list.append(self.helpers.urlparse(self.helpers.urljoin(url, f"objects/pack/pack-{sha1}.pack")))
        if url_list:
            await self.download_files(url_list, folder)

    # Skip regex scan for files larger than this — real git ref/object/info
    # files are small; oversized is almost always a webserver returning HTML.
    _regex_file_max_bytes = 10 * 1024 * 1024
    # Cap download size per file. Real git files are tiny (refs/HEAD <1KB,
    # index a few KB) or pack files (10s of MB legit). Anything bigger is
    # a misconfigured / malicious server returning an error page.
    _download_max_size = "10MB"
    # Cap how deep ``download_object`` recursion can go. Real git object
    # graphs are shallow (commit → tree → blob, depth 10-20 in practice).
    _download_object_max_depth = 100

    async def regex_files(self, regex, folder=None, file=None, files=()):
        results = []
        if folder is not None and folder.is_dir():
            for file_path in folder.rglob("*"):
                if file_path.is_file():
                    results.extend(await self.regex_file(regex, file_path))
        if files:
            for f in files:
                results.extend(await self.regex_file(regex, f))
        if file is not None:
            results.extend(await self.regex_file(regex, file))
        return results

    async def regex_file(self, regex, file=None):
        if file is None or not (file.exists() and file.is_file()):
            return []
        try:
            size = file.stat().st_size
        except OSError:
            return []
        if size > self._regex_file_max_bytes:
            self.debug(f"Skipping regex scan of {file} ({size} bytes)")
            return []
        with file.open("r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
            matches = await self.helpers.re.findall(regex, content)
            if matches:
                return matches
        return []

    async def download_object(self, object, repo_url, repo_folder, _seen=None, _depth=0):
        if _seen is None:
            _seen = set()
        # cycle detection — git tree objects can reference each other in
        # malformed/malicious repos
        if object in _seen:
            return
        _seen.add(object)
        # depth cap — even without cycles, an unbounded tree would burn
        # stack frames + memory per frame
        if _depth >= self._download_object_max_depth:
            self.debug(f"download_object: hit max recursion depth at {object}")
            return
        await self.download_files(
            [self.helpers.urlparse(self.helpers.urljoin(repo_url, f"objects/{object[:2]}/{object[2:]}"))], repo_folder
        )
        output = await self.git_catfile(object, option="-p", folder=repo_folder)
        for obj in await self.helpers.re.findall(self.obj_regex, output):
            await self.download_object(obj, repo_url, repo_folder, _seen=_seen, _depth=_depth + 1)

    async def download_files(self, urls, folder):
        for url in urls:
            git_index = url.path.find(".git")
            file_url = url.geturl()
            filename = (folder / url.path[git_index:]).resolve()
            if not filename.is_relative_to(folder.resolve()):
                self.warning(f"Path traversal detected, skipping: {url.path}")
                continue
            self.helpers.mkdir(filename.parent)
            if hash(str(file_url)) not in self.urls_downloaded:
                self.verbose(f"Downloading {file_url} to {filename}")
                await self.helpers.download(file_url, filename=filename, warn=False, max_size=self._download_max_size)
                self.urls_downloaded.add(hash(str(file_url)))
        if any(folder.rglob("*")):
            return True
        else:
            self.debug(f"Unable to download git files to {folder}")
            return False

    _safe_git_flags = [
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.sshCommand=echo",
        "-c",
        "core.symlinks=false",
        "-c",
        "transfer.fsckObjects=true",
    ]

    async def git_catfile(self, hash, option="-t", folder=Path()):
        command = ["git"] + self._safe_git_flags + ["cat-file", option, hash]
        try:
            output = await self.run_process(command, env={"GIT_TERMINAL_PROMPT": "0"}, cwd=folder, check=True)
        except CalledProcessError:
            return ""

        return output.stdout

    async def git_checkout(self, folder):
        self.helpers.sanitize_git_repo(folder)
        self.verbose(f"Running git checkout to reconstruct the git repository at {folder}")
        command = ["git"] + self._safe_git_flags + ["checkout", "HEAD", "--", "."]
        try:
            await self.run_process(command, env={"GIT_TERMINAL_PROMPT": "0"}, cwd=folder, check=True)
        except CalledProcessError as e:
            self.debug(f"Error running git checkout in {folder}. STDERR: {repr(e.stderr)}")
            self._write_empty_index(folder)

    @staticmethod
    def _write_empty_index(folder):
        """Replace the index with a valid empty one so downstream tools
        never read attacker-controlled index entries (CVE-2025-10283)."""
        import hashlib
        import struct

        header = b"DIRC" + struct.pack(">II", 2, 0)
        index_path = folder / ".git" / "index"
        if index_path.exists():
            index_path.write_bytes(header + hashlib.sha1(header).digest())
