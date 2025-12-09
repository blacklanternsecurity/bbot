from bbot.modules.base import BaseModule
import json


class droopescan(BaseModule):
    watched_events = ["URL"]
    produced_events = ["URL", "VULNERABILITY"]
    flags = ["active", "web-recon"]
    meta = {"description": "Enumerate CMS (Drupal, WP, Joomla, etc.) using Droopescan"}

    
    deps_pipx = ["droopescan"]                     
    options = {"allow_dep_install": True}          

    async def setup(self):
        self.info("Droopescan module loaded")
        return True

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

        except json.JSONDecodeError:
            self.verbose(f"Droopescan returned invalid JSON for {url}")
        except Exception as e:
            self.warning(f"Droopescan error on {url}: {e}")
