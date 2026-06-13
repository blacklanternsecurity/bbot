from .base import BaseModule

import asyncio
from typing import Optional
from pydantic import Field
from bbot.core.config.models import BaseModuleConfig
from domino.DOMino import Domino
from domino.lib.errors import DominoError
from playwright.async_api import async_playwright


class domino(BaseModule):
    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["active", "safe"]
    meta = {
        "description": "Check for Client-side Web Vulnerabilities with DOMino",
        "created_date": "2025-04-08",
        "author": "@liquidsec",
    }

    class Config(BaseModuleConfig):
        rules: Optional[list[str]] = Field(
            default=None,
            description="List of rules to run. None for all rules (default).",
        )
        suppress_parameter_discovery_reports: bool = Field(
            default=True,
            description="Allow parameter discovery to drive rules but suppress reporting the discovery itself",
        )
        browser_instances: int = Field(
            default=2,
            description="Number of browser instances to run concurrently. Each instance uses ~800-1600 MB of memory under load.",
        )

    deps_pip = ["playwright", "d0m1n0"]

    async def setup(self):
        import asyncio.base_subprocess

        def quiet_transport_del(self):
            try:
                self.close()
            except Exception:
                pass

        asyncio.base_subprocess.BaseSubprocessTransport.__del__ = quiet_transport_del

        rules = self.config.get("rules")
        if rules is not None:
            self.rules = rules
        else:
            self.rules = None

        self._browser_count = self.config.get("browser_instances", 2)
        self.module_threads = self._browser_count
        low_estimate = self._browser_count * 800
        high_estimate = self._browser_count * 1600
        self.warning(
            f"The domino module uses Chromium, which consumes a significant amount of memory. "
            f"Your current settings will launch {self._browser_count} instances, for an estimated "
            f"{low_estimate}-{high_estimate} MB. Lower with -c modules.domino.browser_instances=1"
        )

        self.playwright = await async_playwright().start()
        self._browser_pool = asyncio.Queue()
        for _ in range(self._browser_count):
            browser = await self.playwright.chromium.launch(headless=True)
            await self._browser_pool.put(browser)

        self.suppress_parameter_discovery_reports = self.config.get("suppress_parameter_discovery_reports", True)
        return True

    async def _get_browser(self):
        browser = await self._browser_pool.get()
        if not browser.is_connected():
            self.warning("Browser crashed, relaunching")
            browser = await self.playwright.chromium.launch(headless=True)
        return browser

    async def handle_event(self, event):
        url = event.url
        self.debug(f"Domino scanning {url}")
        browser = await self._get_browser()
        try:
            d = Domino(url=url, logger=self.log, json_mode=True, selected_rules=self.rules)
            results = await asyncio.wait_for(d.run(self.playwright, browser), timeout=120)
        except asyncio.TimeoutError:
            self.warning(f"Domino scan timed out after 120s for {url}, killing browser")
            try:
                await browser.close()
            except Exception:
                pass
            browser = await self.playwright.chromium.launch(headless=True)
            return
        except DominoError as e:
            self.hugewarning(f"Error running Domino, setting error state: {e}")
            self.errored = True
            return
        finally:
            await self._browser_pool.put(browser)

        if results:
            for result in results:
                if self.suppress_parameter_discovery_reports and "GET Parameter Access" in result["rule_name"]:
                    continue

                details = result.get("details", [])
                details_string = f" Details: [{','.join(details)}]" if details else ""

                interactions = result.get("interactions", [])
                interactions_string = f" Interactions: [{','.join(interactions)}]" if interactions else ""

                severity = result.get("severity", "medium").upper()
                data = {
                    "name": result["rule_name"],
                    "description": f"{result['description']}.{details_string} Detection URL: [{result['detection_url']}]{interactions_string}",
                    "host": str(event.host),
                    "url": result.get("detection_url") or event.url,
                    "severity": severity,
                    "confidence": "CONFIRMED",
                }
                await self.emit_event(data, "FINDING", event)
        self.debug(f"DOMino scan complete for {url}")

    async def cleanup(self):
        while not self._browser_pool.empty():
            browser = await self._browser_pool.get()
            await browser.close()
        await self.playwright.stop()

    async def filter_event(self, event):
        if "status-200" not in event.tags:
            self.debug(f"Rejecting URL {event.data} due to lack of 200 status code. Tags: {event.tags}")
            return False
        return True
