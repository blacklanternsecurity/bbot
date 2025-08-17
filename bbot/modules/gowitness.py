import os
import asyncio
import aiosqlite
import multiprocessing
import platform
from pathlib import Path
from contextlib import suppress
from shutil import copyfile, copymode

from bbot.modules.base import BaseModule


class gowitness(BaseModule):
    watched_events = ["URL", "SOCIAL"]
    produced_events = ["WEBSCREENSHOT", "URL", "URL_UNVERIFIED", "TECHNOLOGY"]
    flags = ["active", "safe", "web-screenshots"]
    meta = {"description": "Take screenshots of webpages", "created_date": "2022-07-08", "author": "@TheTechromancer"}
    options = {
        "version": "3.0.5",
        "threads": 0,
        "timeout": 10,
        "resolution_x": 1440,
        "resolution_y": 900,
        "output_path": "",
        "social": False,
        "idle_timeout": 1800,
        "chrome_path": "",
    }
    options_desc = {
        "version": "Gowitness version",
        "threads": "How many gowitness threads to spawn (default is number of CPUs x 2)",
        "timeout": "Preflight check timeout",
        "resolution_x": "Screenshot resolution x",
        "resolution_y": "Screenshot resolution y",
        "output_path": "Where to save screenshots",
        "social": "Whether to screenshot social media webpages",
        "idle_timeout": "Skip the current gowitness batch if it stalls for longer than this many seconds",
        "chrome_path": "Path to chrome executable",
    }
    deps_common = ["chromium"]
    deps_pip = ["aiosqlite"]
    deps_ansible = [
        {
            "name": "Download gowitness",
            "get_url": {
                "url": "https://github.com/sensepost/gowitness/releases/download/#{BBOT_MODULES_GOWITNESS_VERSION}/gowitness-#{BBOT_MODULES_GOWITNESS_VERSION}-#{BBOT_OS_PLATFORM}-#{BBOT_CPU_ARCH}",
                "dest": "#{BBOT_TOOLS}/gowitness",
                "mode": "755",
            },
        },
    ]
    _batch_size = 100
    # gowitness accepts SOCIAL events up to distance 2, otherwise it is in-scope-only
    scope_distance_modifier = 2

    async def setup(self):
        num_cpus = multiprocessing.cpu_count()
        default_thread_count = min(20, num_cpus * 2)
        self.timeout = self.config.get("timeout", 10)
        self.idle_timeout = self.config.get("idle_timeout", 1800)
        self.threads = self.config.get("threads", 0)
        if not self.threads:
            self.threads = default_thread_count
        self.proxy = self.scan.web_config.get("http_proxy", "")
        self.resolution_x = self.config.get("resolution_x")
        self.resolution_y = self.config.get("resolution_y")
        self.visit_social = self.config.get("social", True)
        output_path = self.config.get("output_path")
        if output_path:
            self.base_path = Path(output_path) / "gowitness"
        else:
            self.base_path = self.scan.home / "gowitness"

        self.chrome_path = None
        config_chrome_path = self.config.get("chrome_path")
        if config_chrome_path:
            config_chrome_path = Path(config_chrome_path)
            if not config_chrome_path.is_file():
                return False, f"Could not find custom Chrome path at {config_chrome_path}"
            self.chrome_path = config_chrome_path
        else:
            if platform.system() == "Darwin":
                bbot_chrome_path = (
                    self.helpers.tools_dir / "chrome-mac" / "Chromium.app" / "Contents" / "MacOS" / "Chromium"
                )
            else:
                bbot_chrome_path = self.helpers.tools_dir / "chrome-linux" / "chrome"
            if bbot_chrome_path.is_file():
                self.chrome_path = bbot_chrome_path

        # make sure our chrome path works
        chrome_test_pass = False
        if self.chrome_path and self.chrome_path.is_file():
            chrome_test_proc = await self.run_process([str(self.chrome_path), "--version"])
            if getattr(chrome_test_proc, "returncode", 1) == 0:
                self.verbose(f"Found chrome executable at {self.chrome_path}")
                chrome_test_pass = True

        if not chrome_test_pass:
            # last resort - try to find a working chrome install
            for binary in ("Google Chrome", "chrome", "chromium", "chromium-browser"):
                binary_path = self.helpers.which(binary)
                if binary_path and Path(binary_path).is_file():
                    chrome_test_proc = await self.run_process([str(binary_path), "--version"])
                    if getattr(chrome_test_proc, "returncode", 1) == 0:
                        self.verbose(f"Found chrome executable at {binary_path}")
                        chrome_test_pass = True
                        break

        if not chrome_test_pass:
            return (
                False,
                "Failed to set up Google chrome. Please install manually and set `chrome_path`, or try again with --force-deps.",
            )

        # fix ubuntu-specific sandbox bug
        chrome_devel_sandbox = self.helpers.tools_dir / "chrome-linux" / "chrome_sandbox"
        if chrome_devel_sandbox.is_file():
            os.environ["CHROME_DEVEL_SANDBOX"] = str(chrome_devel_sandbox)

        self.db_path = self.base_path / "gowitness.sqlite3"
        self.screenshot_path = self.base_path / "screenshots"
        self.command = self.construct_command()
        self.prepped = False
        self.screenshots_taken = {}
        self.connections_logged = set()
        self.technologies_found = set()
        return True

    def prep(self):
        if not self.prepped:
            self.helpers.mkdir(self.screenshot_path)
            self.db_path.touch()
            with suppress(Exception):
                copyfile(self.helpers.tools_dir / "gowitness", self.base_path / "gowitness")
                copymode(self.helpers.tools_dir / "gowitness", self.base_path / "gowitness")
            self.prepped = True

    async def filter_event(self, event):
        # Ignore URLs that are redirects
        if any(t.startswith("status-30") for t in event.tags):
            return False, "URL is a redirect"
        # ignore events from self
        if event.type == "URL" and event.module == self:
            return False, "event is from self"
        if event.type == "SOCIAL":
            if not self.visit_social:
                return False, "visit_social=False"
        else:
            # Accept out-of-scope SOCIAL pages, but not URLs
            if event.scope_distance > 0:
                return False, "event is not in-scope"
        return True

    async def handle_batch(self, *events):
        self.prep()
        event_dict = {}
        for e in events:
            key = e.data
            if e.type == "SOCIAL":
                key = e.data["url"]
            event_dict[key] = e
        stdin = "\n".join(list(event_dict))
        self.hugeinfo(f"Gowitness input: {stdin}")

        try:
            async for line in self.run_process_live(self.command, input=stdin, idle_timeout=self.idle_timeout):
                self.debug(line)
        except asyncio.exceptions.TimeoutError:
            urls_str = ",".join(event_dict)
            self.warning(f"Gowitness timed out while visiting the following URLs: {urls_str}", trace=False)
            return

        # emit web screenshots
        new_screenshots = await self.get_new_screenshots()
        for filename, screenshot in new_screenshots.items():
            url = screenshot["url"]
            url = self.helpers.clean_url(url).geturl()
            final_url = screenshot["final_url"]
            filename = self.screenshot_path / screenshot["filename"]
            filename = filename.relative_to(self.scan.home)
            # NOTE: this prevents long filenames from causing problems in BBOT, but gowitness will still fail to save it.
            filename = self.helpers.truncate_filename(filename)
            webscreenshot_data = {"path": str(filename), "url": final_url}
            self.hugewarning(event_dict)
            parent_event = event_dict[url]
            await self.emit_event(
                webscreenshot_data,
                "WEBSCREENSHOT",
                parent=parent_event,
                context=f"{{module}} visited {final_url} and saved {{event.type}} to {filename}",
            )

        # emit URLs
        new_network_logs = await self.get_new_network_logs()
        for url, row in new_network_logs.items():
            ip = row["remote_ip"]
            status_code = row["status_code"]
            tags = [f"status-{status_code}", f"ip-{ip}", "spider-danger"]

            _id = row["result_id"]
            parent_url = self.screenshots_taken[_id]
            parent_event = event_dict[parent_url]
            if url and url.startswith("http"):
                await self.emit_event(
                    url,
                    "URL_UNVERIFIED",
                    parent=parent_event,
                    tags=tags,
                    context=f"{{module}} visited {{event.type}}: {url}",
                )

        # emit technologies
        new_technologies = await self.get_new_technologies()
        for row in new_technologies.values():
            parent_id = row["result_id"]
            parent_url = self.screenshots_taken[parent_id]
            parent_event = event_dict[parent_url]
            technology = row["value"]
            tech_data = {"technology": technology, "url": parent_url, "host": str(parent_event.host)}
            await self.emit_event(
                tech_data,
                "TECHNOLOGY",
                parent=parent_event,
                context=f"{{module}} visited {parent_url} and found {{event.type}}: {technology}",
            )

    def construct_command(self):
        # base executable
        command = ["gowitness", "scan"]
        # chrome path
        if self.chrome_path is not None:
            command += ["--chrome-path", str(self.chrome_path)]
        # db path
        command += ["--write-db"]
        command += ["--write-db-uri", f"sqlite://{self.db_path}"]
        # screenshot path
        command += ["--screenshot-path", str(self.screenshot_path)]
        # user agent
        command += ["--chrome-user-agent", f"{self.scan.useragent}"]
        # proxy
        if self.proxy:
            command += ["--chrome-proxy", str(self.proxy)]
        # resolution
        command += ["--chrome-window-x", str(self.resolution_x)]
        command += ["--chrome-window-y", str(self.resolution_y)]
        # threads
        command += ["--threads", str(self.threads)]
        # timeout
        command += ["--timeout", str(self.timeout)]
        # input
        command += ["file", "-f", "-"]
        return command

    async def get_new_screenshots(self):
        screenshots = {}
        if self.db_path.is_file():
            async with aiosqlite.connect(str(self.db_path)) as con:
                con.row_factory = aiosqlite.Row
                con.text_factory = self.helpers.smart_decode
                async with con.execute("SELECT * FROM results") as cur:
                    self.critical(f"CUR: {cur}")
                    async for row in cur:
                        self.critical(f"SCREENSHOT: {row}")
                        row = dict(row)
                        _id = row["id"]
                        if _id not in self.screenshots_taken:
                            self.screenshots_taken[_id] = row["url"]
                            screenshots[_id] = row
        return screenshots

    async def get_new_network_logs(self):
        network_logs = {}
        if self.db_path.is_file():
            async with aiosqlite.connect(str(self.db_path)) as con:
                con.row_factory = aiosqlite.Row
                async with con.execute("SELECT * FROM network_logs") as cur:
                    async for row in cur:
                        self.critical(f"NETWORK LOG: {row}")
                        row = dict(row)
                        url = row["url"]
                        if url not in self.connections_logged:
                            self.connections_logged.add(url)
                            network_logs[url] = row
        return network_logs

    async def get_new_technologies(self):
        technologies = {}
        if self.db_path.is_file():
            async with aiosqlite.connect(str(self.db_path)) as con:
                con.row_factory = aiosqlite.Row
                async with con.execute("SELECT * FROM technologies") as cur:
                    async for row in cur:
                        self.critical(f"TECHNOLOGY: {row}")
                        _id = row["id"]
                        if _id not in self.technologies_found:
                            self.technologies_found.add(_id)
                            row = dict(row)
                            technologies[_id] = row
        return technologies

    async def cur_execute(self, cur, query):
        try:
            return await cur.execute(query)
        except aiosqlite.OperationalError as e:
            self.warning(f"Error executing query: {query}: {e}")
            return []

    async def report(self):
        if self.screenshots_taken:
            self.success(f"{len(self.screenshots_taken):,} web screenshots captured. To view:")
            self.success("    - Start gowitness")
            self.success(f"        - cd {self.base_path} && ./gowitness server")
            self.success("    - Browse to http://localhost:7171")
        else:
            self.info("No web screenshots captured")
