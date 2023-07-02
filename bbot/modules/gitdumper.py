from bbot.modules.base import BaseModule
from urllib.parse import urlparse
from pathlib import Path
import re
import os

import git_dumper


class GitDumper(BaseModule):
    watched_events = ["FINDING"]
    produced_events = ["SOURCE_CODE"]
    flags = ["active", "web-basic", "web-thorough"]
    deps_pip = ["git-dumper"]
    meta = {"description": "Dumps exposed .git repositories to a local folder"}
    in_scope_only = True

    async def setup(self):
        os.environ["PYTHONWARNINGS"] = "ignore"  # git-dumper produces a ton of dumb warnings for SSL
        self.workers = self.config.get("gitdump_workers", 10)
        self.retries = self.config.get("gitdump_retries", 10)
        self.timeout = self.config.get("gitdump_timeout", 10)
        self.headers = {
            "User-Agent": self.config.get(
                "user_agent",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.79 Safari/537.36",
            )
        }
        self.prepped = False
        output_path = self.config.get("output_path")
        if output_path:
            self.base_path = Path(output_path) / "gitdumper"
        else:
            self.base_path = self.scan.home / "gitdumper"
        self.source_code_path = self.base_path / urlparse(str(self.scan.target)).netloc / "src"
        return True

    def prep(self):
        if not self.prepped:
            self.helpers.mkdir(self.source_code_path)
            self.prepped = True

    async def filter_event(self, event):
        if str(event.module) != "git":
            return False
        return True

    async def handle_event(self, event):
        git_url = self.extract_git_url(event.data["url"])
        if os.path.exists(self.source_code_path) and any(os.listdir(self.source_code_path)):
            self.emit_event(
                {
                    "host": str(event.host),
                    "url": git_url,
                    "description": f"Previously Downloaded .git repository: {self.source_code_path}",
                },
                "PREVIOUS_SOURCE_CODE",
                source=event,
            )
        else:
            self.prep()
            self.dump(git_url)
            self.emit_event(
                {"host": str(event.host), "url": git_url, "description": f"Dumping source code for {git_url}"},
                "SOURCE_CODE",
                source=event,
            )

    def dump(self, url):
        return git_dumper.fetch_git(url, self.source_code_path, self.workers, self.retries, self.timeout, self.headers)

    def extract_git_url(self, url):
        parsed_url = urlparse(url)
        path = parsed_url.path
        match = re.search(r"(.*\/\.git\/)", path)
        if match:
            git_url = parsed_url.scheme + "://" + parsed_url.netloc + match.group(1)
            return git_url
