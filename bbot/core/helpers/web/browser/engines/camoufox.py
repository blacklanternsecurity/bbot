"""
Camoufox (https://camoufox.com): a Firefox build that spoofs its fingerprint in the browser itself,
driven through Playwright.
"""

import logging
import platform
from contextlib import suppress

from bbot.errors import BrowserError
from .base import VIEWPORT, BrowserEngine

log = logging.getLogger("bbot.core.helpers.web.browser")

CAMOUFOX_PIP = "camoufox==0.5.8"
# the browser build that camoufox 0.5.8 is pinned to (browser-pin.json in the package)
CAMOUFOX_BUILD = "156.0.1-beta.36"
CAMOUFOX_DIRNAME = f"camoufox-{CAMOUFOX_BUILD}"
CAMOUFOX_DIR = f"#{{BBOT_TOOLS}}/{CAMOUFOX_DIRNAME}"
CAMOUFOX_MARKER = f"{CAMOUFOX_DIR}/.bbot-installed"

# (camoufox asset name, system, architecture, sha256 of the release zip, executable within the extracted zip)
# system and architecture are as reported by both ansible facts and python's platform module
CAMOUFOX_PLATFORMS = [
    ("lin.x86_64", "Linux", "x86_64", "72637885ee67c93466ad377831c647192f8f08fb5c6fd9279de1320b49dd2b53", "camoufox"),
    ("lin.arm64", "Linux", "aarch64", "8b5fd083721c807ee2a752265683482477105052fa0e21739388b527ae067c15", "camoufox"),
    (
        "mac.x86_64",
        "Darwin",
        "x86_64",
        "abe133d2b1c7a8afe5a6af5f44adfd3169b16d4cc2268e99a81a41a6853f5782",
        "Camoufox.app/Contents/MacOS/camoufox",
    ),
    (
        "mac.arm64",
        "Darwin",
        "arm64",
        "0ad5663e40f4a2a836e28747256b79f39a5105905f1b244139a7a391f85fda32",
        "Camoufox.app/Contents/MacOS/camoufox",
    ),
]

# Firefox prefs set on every launch. Its built-in list of HTTPS-only domains would rewrite their http:// loads
FIREFOX_PREFS = {"network.stricttransportsecurity.preloadlist": False}

# appended to camoufox.cfg, which Firefox runs with full privileges at startup. Once any page on a host sends
# Strict-Transport-Security, Firefox rewrites every later http:// load of that host, on any port and in every
# context, to https://; a scan has to load both. Playwright records the header before this blanks it.
HSTS_HOOK_MARKER = "// bbot: ignore Strict-Transport-Security"
HSTS_HOOK = f"""
{HSTS_HOOK_MARKER}
Services.obs.addObserver(
  {{
    observe(channel) {{
      try {{
        channel.QueryInterface(Components.interfaces.nsIHttpChannel).setResponseHeader("Strict-Transport-Security", "", false);
      }} catch (e) {{}}
    }},
  }},
  "http-on-examine-response"
);
"""

# the smallest screen the fingerprint may claim. A window taller or wider than its screen is a giveaway, so this
# leaves room around the viewport for the browser's own toolbars and the OS taskbar
MIN_SCREEN = (VIEWPORT[0] + 160, VIEWPORT[1] + 150)


def _platform_condition(system, arch):
    return f"ansible_facts['system'] == '{system}' and ansible_facts['architecture'] == '{arch}'"


def _camoufox_ansible_tasks():
    supported = " or ".join(f"({_platform_condition(system, arch)})" for _, system, arch, _, _ in CAMOUFOX_PLATFORMS)
    tasks = [
        {
            "name": "Check for a Camoufox build for this platform",
            "fail": {"msg": f"Camoufox {CAMOUFOX_BUILD} has no build for this platform"},
            "when": f"not ({supported})",
        },
        # written only after a complete extraction, so an interrupted install is redone
        {
            "name": "Check for an existing Camoufox install",
            "stat": {"path": CAMOUFOX_MARKER},
            "register": "camoufox_marker",
        },
        {"name": "Create Camoufox directory", "file": {"path": CAMOUFOX_DIR, "state": "directory"}},
        # camoufox otherwise downloads its pinned fingerprint model the first time a browser launches
        {
            "name": "Install Camoufox fingerprint model",
            "command": {
                "argv": [
                    "{{ ansible_python_interpreter }}",
                    "-c",
                    "from camoufox.fpgen_model import ensure_fpgen_model; ensure_fpgen_model()",
                ]
            },
        },
    ]
    for asset, system, arch, sha256, _ in CAMOUFOX_PLATFORMS:
        zip_path = f"#{{BBOT_TEMP}}/camoufox-{CAMOUFOX_BUILD}-{asset}.zip"
        when = f"({_platform_condition(system, arch)}) and not camoufox_marker.stat.exists"
        tasks += [
            {
                "name": f"Download Camoufox ({asset})",
                "get_url": {
                    "url": f"https://github.com/daijro/camoufox/releases/download/v{CAMOUFOX_BUILD}/camoufox-{CAMOUFOX_BUILD}-{asset}.zip",
                    "dest": zip_path,
                    "checksum": f"sha256:{sha256}",
                    "timeout": 600,
                },
                "when": when,
            },
            {
                "name": f"Extract Camoufox ({asset})",
                "unarchive": {"src": zip_path, "dest": CAMOUFOX_DIR, "remote_src": True},
                "when": when,
            },
            {
                "name": f"Remove Camoufox download ({asset})",
                "file": {"path": zip_path, "state": "absent"},
                "when": when,
            },
            {
                "name": f"Mark Camoufox installed ({asset})",
                "file": {"path": CAMOUFOX_MARKER, "state": "touch"},
                "when": when,
            },
        ]
    return tasks


class CamoufoxEngine(BrowserEngine):
    name = "camoufox"
    install_dirname = CAMOUFOX_DIRNAME
    deps = {
        "pip": [CAMOUFOX_PIP],
        "ansible": _camoufox_ansible_tasks(),
    }

    def __init__(self, parent_helper):
        super().__init__(parent_helper)
        web_config = parent_helper.web_config
        self.ws_endpoint = web_config.get("browser_ws_endpoint", "") or ""
        self._http_proxy = web_config.get("http_proxy", None)
        self._http_proxy_exclude = web_config.get("http_proxy_exclude", []) or []
        self._playwright = None

    async def launch(self):
        from playwright.async_api import async_playwright

        if self._playwright is None:
            self._playwright = await async_playwright().start()
        # a Camoufox server started elsewhere (`python -m camoufox server`)
        if self.ws_endpoint:
            log.critical(f"BROWSERDBG camoufox CONNECTING to remote browser server: {self.ws_endpoint}")
            return await self._playwright.firefox.connect(self.ws_endpoint)
        options = await self.parent_helper.run_in_executor_io(self._launch_options)
        log.critical(
            f"BROWSERDBG camoufox launching: executable={options.get('executable_path')} headless={options.get('headless')} "
            f"proxy={options.get('proxy')}"
        )
        return await self._playwright.firefox.launch(**options)

    async def stop(self):
        if self._playwright is not None:
            with suppress(Exception):
                await self._playwright.stop()
            self._playwright = None

    @property
    def errors(self):
        from playwright.async_api import Error as PlaywrightError

        return (PlaywrightError,)

    def _launch_options(self):
        from camoufox import DefaultAddons
        from camoufox.utils import launch_options
        from camoufox.fingerprints import Screen

        kwargs = {
            "executable_path": self.executable_path,
            "headless": True,
            "screen": Screen(min_width=MIN_SCREEN[0], min_height=MIN_SCREEN[1]),
            # uBlock Origin would hide requests (and page content) the scan cares about
            "exclude_addons": [DefaultAddons.UBO],
            "i_know_what_im_doing": True,
            "firefox_user_prefs": FIREFOX_PREFS,
        }
        if self._http_proxy:
            kwargs["proxy"] = {"server": self._http_proxy, "bypass": ",".join(self._http_proxy_exclude)}
        self._add_hsts_hook()
        return launch_options(**kwargs)

    def _add_hsts_hook(self):
        """Add `HSTS_HOOK` to the installed browser's camoufox.cfg, once."""
        config = self.config_path
        if HSTS_HOOK_MARKER not in config.read_text():
            with open(config, "a") as f:
                f.write(HSTS_HOOK)

    @property
    def install_dir(self):
        return self.parent_helper.tools_dir / self.install_dirname

    @property
    def executable_path(self):
        system, machine = platform.system(), platform.machine()
        for _, s, arch, _, executable in CAMOUFOX_PLATFORMS:
            if (s, arch) == (system, machine):
                return self.install_dir / executable
        raise BrowserError(f"Camoufox {CAMOUFOX_BUILD} has no build for {system} {machine}")

    @property
    def config_path(self):
        if platform.system() == "Darwin":
            return self.install_dir / "Camoufox.app/Contents/Resources/camoufox.cfg"
        return self.install_dir / "camoufox.cfg"
