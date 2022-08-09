from pathlib import Path
from contextlib import suppress
from shutil import copyfile, copymode

from bbot.modules.base import BaseModule


class gowitness(BaseModule):
    watched_events = ["URL"]
    produced_events = ["SCREENSHOT"]
    flags = ["active", "web", "safe"]
    meta = {"description": "Take screenshots of webpages"}
    batch_size = 100
    options = {
        "version": "2.4.0",
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
    deps_apt = ["chromium-browser"]
    deps_ansible = [
        {
            "name": "Download gowitness",
            "get_url": {
                "url": "https://github.com/sensepost/gowitness/releases/download/{BBOT_MODULES_GOWITNESS_VERSION}/gowitness-{BBOT_MODULES_GOWITNESS_VERSION}-linux-amd64",
                "dest": "{BBOT_TOOLS}/gowitness",
                "mode": "755",
            },
        }
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
