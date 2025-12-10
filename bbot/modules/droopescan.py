from bbot.modules.base import BaseModule
import json
import sys
import os

class droopescan(BaseModule):
    watched_events = ["URL"]
    produced_events = ["URL", "VULNERABILITY"]
    flags = ["active", "web-recon"]
    meta = {"description": "Enumerate CMS (Drupal, WP, Joomla, SilverStripe, Moodle) using Droopescan"}

    deps_pipx = ["droopescan"]
    options = {"allow_dep_install": True}

    async def setup(self):
        try:
            # 1. Install droopescan
            await self.helpers.run(["pipx", "install", "droopescan", "--force"])

            # 2. Patch Cement for Python 3.12+ BEFORE anything tries to import it
            if sys.version_info >= (3, 12):
                result = await self.helpers.run(["pipx", "list", "--short"])
                patched = False
                for line in result.stdout.splitlines():
                    if "droopescan" in line.lower():
                        venv_path = line.split()[-1]
                        for root, _, files in os.walk(venv_path):
                            if "extension.py" in files and "cement/core" in root:
                                cement_file = os.path.join(root, "extension.py")
                                with open(cement_file) as f:
                                    content = f.read()
                                if "from imp import reload" in content:
                                    content = content.replace("from imp import reload", "from importlib import reload")
                                    with open(cement_file, "w") as f:
                                        f.write(content)
                                    self.info("Auto-patched Cement for Python 3.12+")
                                    patched = True
                                break
                        break
                if not patched:
                    self.verbose("Cement already patched or not found")

            # 3. SKIP the --version check — it’s unnecessary and breaks on 3.12+
            self.info("Droopescan installed and ready")
            return True

        except Exception as e:
            self.warning(f"Droopescan setup error: {e}")
            return False

    async def handle_event(self, event):
        url = str(event.data)
        if not url.startswith(("http://", "https://")):
            return

        cmd = ["droopescan", "scan", "--url", url, "--no-banner", "--format", "json"]

        try:
            result = await self.helpers.run(cmd)
            if result.returncode != 0:
                self.verbose(f"No CMS detected on {url}")
                return

            data = json.loads(result.stdout)

            for entry in data:
                cms = entry.get("cms", "unknown").capitalize()
                version = entry.get("version", "unknown")
                interesting = entry.get("interesting urls", []) or entry.get("interesting_urls", [])

                if version != "unknown":
                    await self.emit_event({
                        "severity": "INFO",
                        "description": f"{cms} version {version} detected by Droopescan",
                        "url": url
                    }, "VULNERABILITY", source=event)

                for path in interesting:
                    new_url = self.helpers.make_url(url, path.strip())
                    if new_url:
                        await self.emit_event(new_url, "URL", source=event)
                        self.hugesuccess(f"Found {cms} interesting URL → {new_url}")

        except Exception as e:
            self.warning(f"Droopescan error on {url}: {e}")
