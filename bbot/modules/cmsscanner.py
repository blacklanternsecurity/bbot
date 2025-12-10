from bbot.modules.base import BaseModule
import json

class cmsscanner(BaseModule):
    watched_events = ["URL"]
    produced_events = ["URL", "VULNERABILITY"]
    flags = ["active", "web-recon"]
    meta = {
        "description": "Modern CMS scanner — supports 30+ platforms (WordPress, Drupal, Joomla, Magento, etc.)",
        "created_date": "2025-04-05",
        "author": "@Nasaltron"
    }

    deps_pipx = ["cmsscanner"]
    options = {"allow_dep_install": True}

    async def setup(self):
        self.info("cmsscanner module loaded — using the modern, maintained scanner")
        return True

    async def handle_event(self, event):
        url = str(event.data).rstrip("/")
        if not url.startswith(("http://", "https://")):
            return

        cmd = ["cmsscanner", url, "--json", "--no-color"]

        try:
            result = await self.helpers.run(cmd)
            if result.returncode != 0:
                self.verbose(f"cmsscanner found nothing on {url}")
                return

            data = json.loads(result.stdout)

            for cms in data.get("cms", []):
                name = cms.get("name", "Unknown CMS")
                version = cms.get("version")
                if version:
                    await self.emit_event({
                        "severity": "INFO",
                        "description": f"{name} {version} detected by cmsscanner",
                        "url": url
                    }, "VULNERABILITY", source=event)

                for path in cms.get("interesting", []):
                    new_url = self.helpers.make_url(url, path.lstrip("/"))
                    if new_url:
                        await self.emit_event(new_url, "URL", source=event)
                        self.hugesuccess(f"Found {name} interesting URL → {new_url}")

        except Exception as e:
            self.verbose(f"cmsscanner error on {url}: {e}")
