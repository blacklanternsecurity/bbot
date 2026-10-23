"""
Real browser support, driven by Camoufox: screenshots, rendered DOMs, and a fallback for pages
behind a JavaScript challenge that no HTTP client can pass.

Off unless `web.enable_browser` is set. Nothing at import time touches Camoufox or Playwright,
so BBOT runs normally on a machine where they were never installed.
"""

CAMOUFOX_PIP = "camoufox==0.5.8"
# the browser build that camoufox 0.5.8 is pinned to (browser-pin.json in the package)
CAMOUFOX_BUILD = "156.0.1-beta.36"
CAMOUFOX_DIR = f"#{{BBOT_TOOLS}}/camoufox-{CAMOUFOX_BUILD}"
CAMOUFOX_MARKER = f"{CAMOUFOX_DIR}/.bbot-installed"

# (camoufox asset name, ansible system, ansible architecture, sha256 of the release zip)
CAMOUFOX_PLATFORMS = [
    ("lin.x86_64", "Linux", "x86_64", "72637885ee67c93466ad377831c647192f8f08fb5c6fd9279de1320b49dd2b53"),
    ("lin.arm64", "Linux", "aarch64", "8b5fd083721c807ee2a752265683482477105052fa0e21739388b527ae067c15"),
    ("mac.x86_64", "Darwin", "x86_64", "abe133d2b1c7a8afe5a6af5f44adfd3169b16d4cc2268e99a81a41a6853f5782"),
    ("mac.arm64", "Darwin", "arm64", "0ad5663e40f4a2a836e28747256b79f39a5105905f1b244139a7a391f85fda32"),
]


def _platform_condition(system, arch):
    return f"ansible_facts['system'] == '{system}' and ansible_facts['architecture'] == '{arch}'"


def _camoufox_ansible_tasks():
    supported = " or ".join(f"({_platform_condition(system, arch)})" for _, system, arch, _ in CAMOUFOX_PLATFORMS)
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
    for asset, system, arch, sha256 in CAMOUFOX_PLATFORMS:
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


class BrowserHelper:
    # installed by the deps installer only when web.enable_browser is on, never as part of a module's deps
    config_switch = ("web", "enable_browser")
    deps = {
        "pip": [CAMOUFOX_PIP],
        "ansible": _camoufox_ansible_tasks(),
    }
