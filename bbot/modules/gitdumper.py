from pathlib import Path
from bs4 import BeautifulSoup as BS
from urllib.parse import urljoin
from bbot.modules.base import BaseModule


class GitDumper(BaseModule):
    watched_events = ["FINDING"]
    produced_events = ["SOURCE_CODE"]
    deps_pip = ["bs4"]
    flags = ["active", "web-basic", "web-thorough"]
    meta = {"description": "Dumps source code from exposed .git directories to a local folder"}
    in_scope_only = True

    async def setup(self):
        self.src_path = self.scan.home / self.helpers.urlparse(str(self.scan.target)).netloc / "src"
        self.git_url = ""
        return True

    async def filter_event(self, event):
        if str(event.module) != "git":
            return False
        return True

    async def handle_event(self, event):
        self.git_url = self.extract_git_url(event.data["url"])
        visited = set()
        await self.dump_git(self.git_url, visited, self.src_path)
        self.debug("Running git checkout")
        command = ["git", "checkout", "."]
        self.helpers.os.chdir(self.src_path)
        async for line in self.helpers.run_live(command):
            self.debug(line)
        self.emit_event(
            {
                "host": str(event.host),
                "url": self.git_url,
                "description": f"Dumped source code from {self.git_url} to {self.src_path}",
            },
            "SOURCE_CODE",
            source=event,
        )

    async def dump_git(self, url, visited=None, output_folder=None):
        if visited is None:
            visited = set()
        if output_folder is None:
            output_folder = ""
        links = set()
        if url not in visited:
            visited.add(url)
            response = await self.helpers.request(url)
            if response.status_code == 200:
                soup = BS(response.text, "html.parser")
                for link in soup.find_all("a"):
                    href = link.get("href")
                    absolute_url = urljoin(url, href)
                    if not href.startswith("?") and href != "/" and absolute_url != url:
                        self.debug(f"Making request to: {absolute_url}")
                        path = self.helpers.urlparse(absolute_url).path
                        links.add(absolute_url)
                        if href.endswith("/") and absolute_url not in visited:
                            local_path = self.get_local_path(output_folder, path[1:])
                            self.helpers.os.makedirs(local_path, exist_ok=True)
                            subfolder_links = await self.dump_git(absolute_url, visited, output_folder)
                            links.update(subfolder_links)
                        else:
                            file_path = Path(self.get_local_path(output_folder, path[1:]))
                            if not self.helpers.os.path.exists(self.helpers.os.path.dirname(file_path)):
                                self.helpers.os.makedirs(self.helpers.os.path.dirname(file_path), exist_ok=True)
                            if not self.helpers.os.path.isdir(file_path):
                                self.debug(f"Attempting to download {absolute_url} to {str(file_path)}")
                                await self.helpers.download(absolute_url, filename=file_path)
        return links

    def extract_git_url(self, url):
        parsed_url = self.helpers.urlparse(url)
        path = parsed_url.path
        match = self.helpers.re.search(r"(.*\/\.git\/)", path)
        if match:
            git_url = parsed_url.scheme + "://" + parsed_url.netloc + match.group(1)
            return git_url

    def get_local_path(self, output_folder, path):
        return self.helpers.os.path.join(output_folder, path)
