from pathlib import Path
from contextlib import suppress
from shutil import copyfile, copymode

from bbot.modules.base import BaseModule


class gowitness(BaseModule):
    watched_events = ["URL"]
    produced_events = ["SCREENSHOT"]
    flags = ["active", "safe", "web-screenshots"]
    meta = {"description": "Take screenshots of webpages"}
    batch_size = 100
    options = {
        "version": "2.4.2",
        "threads": 4,
        "timeout": 10,
        "resolution_x": 1440,
        "resolution_y": 900,
        "output_path": "",
    }
    options_desc = {
        "version": "gowitness version",
        "threads": "threads used to run",
        "timeout": "preflight check timeout",
        "resolution_x": "screenshot resolution x",
        "resolution_y": "screenshot resolution y",
        "output_path": "where to save screenshots",
    }
    deps_ansible = [
        {
            "name": "Install Chromium (Non-Debian)",
            "package": {"name": "chromium", "state": "present"},
            "become": True,
            "when": "ansible_facts['os_family'] != 'Debian'",
            "ignore_errors": True,
        },
        {
            "name": "Install Chromium dependencies (Debian)",
            "package": {
                "name": "libasound2,libatk-bridge2.0-0,libatk1.0-0,libcairo2,libcups2,libdrm2,libgbm1,libnss3,libpango-1.0-0,libxcomposite1,libxdamage1,libxfixes3,libxkbcommon0,libxrandr2",
                "state": "present",
            },
            "become": True,
            "when": "ansible_facts['os_family'] == 'Debian'",
            "ignore_errors": True,
        },
        {
            "name": "Get latest Chromium version (Debian)",
            "uri": {
                "url": "https://www.googleapis.com/download/storage/v1/b/chromium-browser-snapshots/o/Linux_x64%2FLAST_CHANGE?alt=media",
                "return_content": True,
            },
            "register": "chromium_version",
            "when": "ansible_facts['os_family'] == 'Debian'",
            "ignore_errors": True,
        },
        {
            "name": "Download Chromium (Debian)",
            "unarchive": {
                "src": "https://www.googleapis.com/download/storage/v1/b/chromium-browser-snapshots/o/Linux_x64%2F{{ chromium_version.content }}%2Fchrome-linux.zip?alt=media",
                "remote_src": True,
                "dest": "#{BBOT_TOOLS}",
                "creates": "#{BBOT_TOOLS}/chrome-linux",
            },
            "when": "ansible_facts['os_family'] == 'Debian'",
            "ignore_errors": True,
        },
        {
            "name": "Download gowitness",
            "get_url": {
                "url": "https://github.com/sensepost/gowitness/releases/download/#{BBOT_MODULES_GOWITNESS_VERSION}/gowitness-#{BBOT_MODULES_GOWITNESS_VERSION}-#{BBOT_OS_PLATFORM}-#{BBOT_CPU_ARCH}",
                "dest": "#{BBOT_TOOLS}/gowitness",
                "mode": "755",
            },
        },
    ]
    # visit up to and including the scan's configured search distance
    # this is one hop further than the default
    scope_distance_modifier = 0

    def setup(self):
        self.timeout = self.config.get("timeout", 10)
        self.threads = self.config.get("threads", 4)
        self.proxy = self.scan.config.get("http_proxy", "")
        self.resolution_x = self.config.get("resolution_x")
        self.resolution_y = self.config.get("resolution_y")
        output_path = self.config.get("output_path")
        if output_path:
            self.base_path = Path(output_path) / "gowitness"
        else:
            self.base_path = self.scan.home / "gowitness"
        self.chrome_path = None
        custom_chrome_path = self.helpers.tools_dir / "chrome-linux" / "chrome"
        if custom_chrome_path.is_file():
            self.chrome_path = custom_chrome_path
        self.db_path = self.base_path / "gowitness.sqlite3"
        self.screenshot_path = self.base_path / "screenshots"
        self.command = self.construct_command()
        self.prepped = False
        return True

    def prep(self):
        if not self.prepped:
            self.helpers.mkdir(self.screenshot_path)
            self.db_path.touch()
            with suppress(Exception):
                copyfile(self.helpers.tools_dir / "gowitness", self.base_path / "gowitness")
                copymode(self.helpers.tools_dir / "gowitness", self.base_path / "gowitness")
            self.prepped = True

    def filter_event(self, event):
        # Ignore URLs that are redirects
        if any(t.startswith("status-30") for t in event.tags):
            return False
        return True

    def handle_batch(self, *events):
        self.prep()
        stdin = "\n".join([str(e.data) for e in events])
        for line in self.helpers.run_live(self.command, input=stdin):
            self.debug(line)

    def construct_command(self):
        # base executable
        command = ["gowitness"]
        # chrome path
        if self.chrome_path is not None:
            command += ["--chrome-path", str(self.chrome_path)]
        # db path
        command += ["--db-path", str(self.db_path)]
        # screenshot path
        command += ["--screenshot-path", str(self.screenshot_path)]
        # user agent
        command += ["--user-agent", f"{self.scan.useragent}"]
        # proxy
        if self.proxy:
            command += ["--proxy", str(self.proxy)]
        # resolution
        command += ["--resolution-x", str(self.resolution_x)]
        command += ["--resolution-y", str(self.resolution_y)]
        # input
        command += ["file", "-f", "-"]
        # threads
        command += ["--threads", str(self.threads)]
        return command
