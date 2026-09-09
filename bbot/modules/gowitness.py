import os
import sys
import asyncio
import aiosqlite
import multiprocessing
import platform
from pathlib import Path

from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class gowitness(BaseModule):
    watched_events = ["URL", "SOCIAL"]
    produced_events = ["WEBSCREENSHOT", "URL", "URL_UNVERIFIED", "TECHNOLOGY"]
    flags = ["safe", "active", "web-screenshots"]
    meta = {"description": "Take screenshots of webpages", "created_date": "2022-07-08", "author": "@TheTechromancer"}

    class Config(BaseModuleConfig):
        version: str = Field("3.1.1", description="Gowitness version")
        threads: int = Field(0, description="How many gowitness threads to spawn (default is number of CPUs x 2)")
        timeout: int = Field(10, description="Preflight check timeout")
        resolution_x: int = Field(1440, description="Screenshot resolution x")
        resolution_y: int = Field(900, description="Screenshot resolution y")
        output_path: str = Field("", description="Where to save screenshots")
        social: bool = Field(False, description="Whether to screenshot social media webpages")
        idle_timeout: int = Field(
            1800, description="Skip the current gowitness batch if it stalls for longer than this many seconds"
        )
        chrome_path: str = Field("", description="Path to chrome executable")

    deps_common = ["chromium"]
    deps_pip = ["aiosqlite"]
    deps_ansible = [
        {
            "name": "Download gowitness",
            "get_url": {
                "url": "https://github.com/sensepost/gowitness/releases/download/#{BBOT_MODULES_GOWITNESS_VERSION}/gowitness-#{BBOT_MODULES_GOWITNESS_VERSION}-#{BBOT_OS_PLATFORM}-#{BBOT_CPU_ARCH_GOLANG}",
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

        self.screenshot_path = self.base_path / "screenshots"
        self.helpers.mkdir(self.screenshot_path)
        self.screenshot_count = 0
        return True

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

    @staticmethod
    def _url_key(parsed_url):
        """Scheme-and-port-agnostic key for URL correlation.

        Gowitness may change both the scheme and port of a URL it visits
        (e.g. recording http://host:443/ for an input of http://host/ when
        the server redirects to HTTPS). We key only by hostname + path so
        correlation succeeds regardless of scheme/port differences.
        """
        hostname = parsed_url.hostname or ""
        path = parsed_url.path or "/"
        return f"{hostname}{path}"

    def _resolve_parent(self, db_url):
        """Match a URL from the gowitness DB back to the original input event.

        Tries exact match first, then falls back to a scheme-and-port-agnostic
        lookup for cases where gowitness transforms the stored URL (e.g. after
        a redirect from http to https).
        """
        parent = self._event_dict.get(db_url)
        if parent is None:
            parent = self._event_dict_loose.get(self._url_key(self.helpers.urlparse(db_url)))
        return parent

    async def handle_batch(self, *events):
        # Each batch gets its own throwaway database. Nothing is persisted once the
        # batch's events are emitted, which keeps memory flat regardless of scan size
        # (gowitness's network_logs table grows enormous on large scans otherwise).
        db_path = self.scan.temp_dir / f"gowitness_{self.helpers.rand_string()}.sqlite3"
        self._event_dict = {}
        self._event_dict_loose = {}
        stdin_urls = []
        for e in events:
            url = e.url if e.type == "SOCIAL" else (e.url or e.data)
            stdin_urls.append(url)
            self._event_dict[url] = e
            self._event_dict_loose.setdefault(self._url_key(self.helpers.urlparse(url)), e)
        stdin = "\n".join(stdin_urls)

        try:
            try:
                async for line in self.run_process_live(
                    self.construct_command(db_path), input=stdin, idle_timeout=self.idle_timeout
                ):
                    self.debug(line)
            except asyncio.exceptions.TimeoutError:
                urls_str = ",".join(self._event_dict)
                self.warning(f"Gowitness timed out while visiting the following URLs: {urls_str}", trace=False)
                return

            try:
                await self.emit_results(db_path)
            except aiosqlite.Error as e:
                # gowitness exited before writing a usable database (chrome likely failed to
                # launch), so the whole batch produced nothing
                self.warning(
                    f"Gowitness produced no results for {len(events)} URLs; chrome may have failed to launch ({e})",
                    trace=False,
                )
        finally:
            # discard the batch database; the screenshots themselves live on disk
            db_path.unlink(missing_ok=True)

    async def emit_results(self, db_path):
        if not db_path.is_file():
            return
        async with aiosqlite.connect(str(db_path)) as con:
            con.row_factory = aiosqlite.Row
            con.text_factory = self.helpers.smart_decode

            # gowitness result_id -> the URL it visited, used to attribute child rows back to their page
            result_urls = {}

            # screenshots
            async with con.execute("SELECT * FROM results") as cur:
                async for row in cur:
                    row = dict(row)
                    raw_url = row["url"]
                    result_urls[row["id"]] = raw_url
                    final_url = row["final_url"]
                    filename = self.screenshot_path / row["filename"]
                    filename = filename.relative_to(self.scan.home)
                    # NOTE: this prevents long filenames from causing problems in BBOT, but gowitness will still fail to save it.
                    filename = self.helpers.truncate_filename(filename)
                    parent_event = self._resolve_parent(raw_url)
                    if parent_event is None:
                        self.warning(f"Could not correlate screenshot to parent event for URL: {raw_url}")
                        continue
                    await self.emit_event(
                        {"path": str(filename), "url": final_url},
                        "WEBSCREENSHOT",
                        parent=parent_event,
                        context=f"{{module}} visited {final_url} and saved {{event.type}} to {filename}",
                    )
                    self.screenshot_count += 1

            # network logs -> URLs (one event per unique URL within the batch)
            seen_urls = set()
            async with con.execute("SELECT * FROM network_logs") as cur:
                async for row in cur:
                    row = dict(row)
                    url = row["url"]
                    if not (url and url.startswith("http")) or url in seen_urls:
                        continue
                    seen_urls.add(url)
                    raw_parent_url = result_urls.get(row["result_id"])
                    if raw_parent_url is None:
                        continue
                    parent_event = self._resolve_parent(raw_parent_url)
                    if parent_event is None:
                        self.warning(f"Could not correlate network log to parent event for URL: {raw_parent_url}")
                        continue
                    ip = row["remote_ip"]
                    url_event = self.make_event(
                        url,
                        "URL_UNVERIFIED",
                        parent=parent_event,
                        tags=[f"status-{row['status_code']}", "spider-danger"],
                        context=f"{{module}} visited {{event.type}}: {url}",
                    )
                    if url_event and ip:
                        url_event.resolved_hosts = (sys.intern(ip),)
                    await self.emit_event(url_event)

            # technologies
            async with con.execute("SELECT * FROM technologies") as cur:
                async for row in cur:
                    row = dict(row)
                    raw_parent_url = result_urls.get(row["result_id"])
                    if raw_parent_url is None:
                        continue
                    parent_event = self._resolve_parent(raw_parent_url)
                    if parent_event is None:
                        self.warning(f"Could not correlate technology to parent event for URL: {raw_parent_url}")
                        continue
                    technology = row["value"]
                    parent_url = self.helpers.clean_url(raw_parent_url).geturl()
                    await self.emit_event(
                        {"technology": technology, "url": parent_url, "host": str(parent_event.host)},
                        "TECHNOLOGY",
                        parent=parent_event,
                        context=f"{{module}} visited {parent_url} and found {{event.type}}: {technology}",
                    )

    def construct_command(self, db_path):
        # base executable
        command = ["gowitness", "scan"]
        # chrome path
        if self.chrome_path is not None:
            command += ["--chrome-path", str(self.chrome_path)]
        # db path
        command += ["--write-db"]
        command += ["--write-db-uri", f"sqlite://{db_path}"]
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

    async def report(self):
        if self.screenshot_count:
            self.success(f"{self.screenshot_count:,} web screenshots captured. Saved to: {self.screenshot_path}")
        else:
            self.info("No web screenshots captured")
